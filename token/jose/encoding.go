/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jose

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode"

	"authelia.com/provider/oauth2/token/jose/json"
)

// errNonCanonicalBase64 is returned for a base64url encoding whose final quantum carries non-zero unused bits.
var errNonCanonicalBase64 = errors.New("go-jose/go-jose: non-canonical base64url encoding")

// base64URLDecode decodes s and rejects a non-canonical encoding.
//
// RFC 4648 Section 3.5 requires an encoder to set the unused bits of the final quantum to zero, but Go's decoder
// accepts them set, so several distinct strings decode to the same octets and every one of them then verifies. A
// token therefore has no single spelling, which defeats any cache keyed on the token string.
func base64URLDecode(s string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}

	if base64.RawURLEncoding.EncodeToString(decoded) != s {
		return nil, errNonCanonicalBase64
	}

	return decoded, nil
}

func containsWhitespace(data string) bool {
	return strings.ContainsFunc(data, unicode.IsSpace)
}

// Helper function to serialize known-good objects.
// Precondition: value is not a nil pointer.
func mustSerializeJSON(value any) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	// We never want to serialize the top-level value "null," since it's not a
	// valid JOSE message. But if a caller passes in a nil pointer to this method,
	// MarshalJSON will happily serialize it as the top-level value "null". If
	// that value is then embedded in another operation, for instance by being
	// base64-encoded and fed as input to a signing algorithm
	// (https://github.com/go-jose/go-jose/issues/22), the result will be
	// incorrect. Because this method is intended for known-good objects, and a nil
	// pointer is not a known-good object, we are free to panic in this case.
	// Note: It's not possible to directly check whether the data pointed at by an
	// interface is a nil pointer, so we do this hacky workaround.
	// https://groups.google.com/forum/#!topic/golang-nuts/wnH302gBa4I
	if string(out) == "null" {
		panic("Tried to serialize a nil pointer.")
	}
	return out
}

// Perform compression based on algorithm
func compress(algorithm CompressionAlgorithm, input []byte) ([]byte, error) {
	switch algorithm {
	case DEFLATE:
		return deflate(input)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// Perform decompression based on algorithm
func decompress(algorithm CompressionAlgorithm, input []byte) ([]byte, error) {
	switch algorithm {
	case DEFLATE:
		return inflate(input)
	default:
		return nil, ErrUnsupportedAlgorithm
	}
}

// deflate compresses the input.
func deflate(input []byte) ([]byte, error) {
	output := new(bytes.Buffer)

	// Writing to byte buffer, err is always nil
	writer, _ := flate.NewWriter(output, 1)
	_, _ = io.Copy(writer, bytes.NewBuffer(input))

	err := writer.Close()
	return output.Bytes(), err
}

// inflate decompresses the input.
//
// Errors if the decompressed data would be >250kB or >10x the size of the
// compressed data, whichever is larger.
func inflate(input []byte) ([]byte, error) {
	output := new(bytes.Buffer)
	reader := flate.NewReader(bytes.NewBuffer(input))

	// The cap is on the output, not the input: a small compressed payload must not be able to expand without
	// bound. The name says which side it governs, since the function is handling both.
	maxDecompressedSize := max(250_000, 10*int64(len(input)))

	limit := maxDecompressedSize + 1
	n, err := io.CopyN(output, reader, limit)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n == limit {
		return nil, fmt.Errorf("uncompressed data would be too large (>%d bytes)", maxDecompressedSize)
	}

	err = reader.Close()
	return output.Bytes(), err
}

// byteBuffer represents a slice of bytes that can be serialized to url-safe base64.
type byteBuffer struct {
	data []byte
}

func newBuffer(data []byte) *byteBuffer {
	if data == nil {
		return nil
	}
	return &byteBuffer{
		data: data,
	}
}

func newFixedSizeBuffer(data []byte, length int) *byteBuffer {
	if len(data) > length {
		panic("go-jose/go-jose: invalid call to newFixedSizeBuffer (len(data) > length)")
	}
	pad := make([]byte, length-len(data))
	return newBuffer(append(pad, data...))
}

func newBufferFromInt(num uint64) *byteBuffer {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, num)
	return newBuffer(bytes.TrimLeft(data, "\x00"))
}

func (b *byteBuffer) MarshalJSON() ([]byte, error) {
	return json.Marshal(b.base64())
}

func (b *byteBuffer) UnmarshalJSON(data []byte) error {
	var encoded string
	err := json.Unmarshal(data, &encoded)
	if err != nil {
		return err
	}

	if encoded == "" {
		return nil
	}

	decoded, err := base64URLDecode(encoded)
	if err != nil {
		return err
	}

	*b = *newBuffer(decoded)

	return nil
}

func (b *byteBuffer) base64() string {
	// Handling nil here mirrors bytes below. newBuffer returns nil for a nil
	// slice, and newBufferFromInt(0) reaches it because bytes.TrimLeft reports a
	// fully trimmed slice as nil.
	if b == nil {
		return ""
	}

	return base64.RawURLEncoding.EncodeToString(b.data)
}

func (b *byteBuffer) bytes() []byte {
	// Handling nil here allows us to transparently handle nil slices when serializing.
	if b == nil {
		return nil
	}
	return b.data
}

func (b byteBuffer) bigInt() *big.Int {
	return new(big.Int).SetBytes(b.data)
}

// toInt returns the buffer as an int, and reports a value which does not fit rather than truncating it. The only
// caller is the RSA public exponent, where silently keeping the low bits made two JWKs differing above that
// boundary parse to one key -- and, since rsaThumbprintInput re-encodes from the result, share a thumbprint.
func (b byteBuffer) toInt() (int, error) {
	value := b.bigInt()

	if !value.IsInt64() {
		return 0, errors.New("go-jose/go-jose: value is too large to be represented as an integer")
	}

	wide := value.Int64()

	if narrow := int(wide); int64(narrow) == wide {
		return narrow, nil
	}

	return 0, errors.New("go-jose/go-jose: value is too large to be represented as an integer")
}

func base64EncodeLen(sl []byte) int {
	return base64.RawURLEncoding.EncodedLen(len(sl))
}

func base64JoinWithDots(inputs ...[]byte) string {
	if len(inputs) == 0 {
		return ""
	}

	// Count of dots.
	totalCount := len(inputs) - 1

	for _, input := range inputs {
		totalCount += base64EncodeLen(input)
	}

	out := make([]byte, totalCount)
	startEncode := 0
	for i, input := range inputs {
		base64.RawURLEncoding.Encode(out[startEncode:], input)

		if i == len(inputs)-1 {
			continue
		}

		startEncode += base64EncodeLen(input)
		out[startEncode] = '.'
		startEncode++
	}

	return string(out)
}
