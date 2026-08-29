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
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestDeflateRoundtrip(t *testing.T) {
	original := []byte("Lorem ipsum dolor sit amet")

	compressed, err := deflate(original)
	if err != nil {
		panic(err)
	}

	output, err := inflate(compressed)
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(output, original) {
		t.Error("Input and output do not match")
	}
}

func TestInvalidCompression(t *testing.T) {
	_, err := compress("XYZ", []byte{})
	if err == nil {
		t.Error("should not accept invalid algorithm")
	}

	_, err = decompress("XYZ", []byte{})
	if err == nil {
		t.Error("should not accept invalid algorithm")
	}

	_, err = decompress(DEFLATE, []byte{1, 2, 3, 4})
	if err == nil {
		t.Error("should not accept invalid data")
	}
}

// TestLargeZip tests that we can decompress a large input, so long as its
// compression ratio is reasonable.
func TestLargeZip(t *testing.T) {
	input := new(bytes.Buffer)
	_, err := io.CopyN(input, rand.Reader, 251_000)
	if err != nil {
		t.Fatalf("generating input: %s", err)
	}
	compressed, err := compress(DEFLATE, input.Bytes())
	if err != nil {
		t.Errorf("compressing: %s", err)
	}
	t.Logf("compression ratio: %g", float64(len(input.Bytes()))/float64(len(compressed)))
	_, err = decompress(DEFLATE, compressed)
	if err != nil {
		t.Errorf("decompressing large input with low compression ratio: %s", err)
	}
}

func TestZipBomb(t *testing.T) {
	input := strings.Repeat("a", 251_000)
	compressed, err := compress(DEFLATE, []byte(input))
	if err != nil {
		t.Errorf("compressing: %s", err)
	}
	t.Logf("compression ratio: %d %g", len(compressed), float64(len(input))/float64(len(compressed)))
	out, err := decompress(DEFLATE, compressed)
	if err == nil {
		t.Errorf("expected error decompressing zip bomb, got none. output size %d", len(out))
	}
}

func TestByteBufferTrim(t *testing.T) {
	buf := newBufferFromInt(1)
	if !bytes.Equal(buf.data, []byte{1}) {
		t.Error("Byte buffer for integer '1' should contain [0x01]")
	}

	buf = newBufferFromInt(65537)
	if !bytes.Equal(buf.data, []byte{1, 0, 1}) {
		t.Error("Byte buffer for integer '65537' should contain [0x01, 0x00, 0x01]")
	}
}

func TestFixedSizeBuffer(t *testing.T) {
	data0 := []byte{}
	data1 := []byte{1}
	data2 := []byte{1, 2}
	data3 := []byte{1, 2, 3}
	data4 := []byte{1, 2, 3, 4}

	buf0 := newFixedSizeBuffer(data0, 4)
	buf1 := newFixedSizeBuffer(data1, 4)
	buf2 := newFixedSizeBuffer(data2, 4)
	buf3 := newFixedSizeBuffer(data3, 4)
	buf4 := newFixedSizeBuffer(data4, 4)

	if !bytes.Equal(buf0.data, []byte{0, 0, 0, 0}) {
		t.Error("Invalid padded buffer for buf0")
	}
	if !bytes.Equal(buf1.data, []byte{0, 0, 0, 1}) {
		t.Error("Invalid padded buffer for buf1")
	}
	if !bytes.Equal(buf2.data, []byte{0, 0, 1, 2}) {
		t.Error("Invalid padded buffer for buf2")
	}
	if !bytes.Equal(buf3.data, []byte{0, 1, 2, 3}) {
		t.Error("Invalid padded buffer for buf3")
	}
	if !bytes.Equal(buf4.data, []byte{1, 2, 3, 4}) {
		t.Error("Invalid padded buffer for buf4")
	}
}

func TestSerializeJSONRejectsNil(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), "nil pointer") {
			t.Error("serialize function should not accept nil pointer")
		}
	}()

	mustSerializeJSON(nil)
}

func TestFixedSizeBufferTooLarge(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Error("should not be able to create fixed size buffer with oversized data")
		}
	}()

	newFixedSizeBuffer(make([]byte, 2), 1)
}

// A pooled and reset flate writer must behave exactly as a freshly constructed one, both in the bytes it produces and
// in never carrying anything of the previous plaintext into the next stream.
func TestDeflateIsUnaffectedByWriterReuse(t *testing.T) {
	first := []byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`)
	second := []byte(strings.Repeat("a distinctive secret which must not reappear ", 32))

	firstCompressed, err := deflate(first)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}

	secondCompressed, err := deflate(second)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}

	firstAgain, err := deflate(first)
	if err != nil {
		t.Fatalf("deflate: %v", err)
	}

	if !bytes.Equal(firstCompressed, firstAgain) {
		t.Error("deflate produced different output for the same input after the writer had been reused")
	}

	for _, tc := range []struct {
		name       string
		compressed []byte
		expected   []byte
	}{
		{"ShouldRoundTripFirst", firstCompressed, first},
		{"ShouldRoundTripSecond", secondCompressed, second},
		{"ShouldRoundTripFirstAfterReuse", firstAgain, first},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := decompress(DEFLATE, tc.compressed)
			if err != nil {
				t.Fatalf("decompress: %v", err)
			}

			if !bytes.Equal(out, tc.expected) {
				t.Errorf("roundtrip returned %q, want %q", out, tc.expected)
			}
		})
	}
}

func TestDeflateIsConcurrencySafe(t *testing.T) {
	inputs := [][]byte{
		[]byte(`{"sub":"1234567890"}`),
		[]byte(strings.Repeat("b", 4096)),
		[]byte("Lorem ipsum dolor sit amet"),
	}

	expected := make([][]byte, len(inputs))

	for i, input := range inputs {
		out, err := deflate(input)
		if err != nil {
			t.Fatalf("deflate: %v", err)
		}

		expected[i] = out
	}

	var wg sync.WaitGroup

	errs := make(chan error, 64)

	for i := range 64 {
		wg.Add(1)

		go func(n int) {
			defer wg.Done()

			out, err := deflate(inputs[n%len(inputs)])
			if err != nil {
				errs <- err

				return
			}

			if !bytes.Equal(out, expected[n%len(inputs)]) {
				errs <- fmt.Errorf("goroutine %d produced %d bytes, want %d", n, len(out), len(expected[n%len(inputs)]))
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func BenchmarkDeflate(b *testing.B) {
	input := []byte(`{"sub":"1234567890","name":"John Doe","iat":1516239022}`)

	for b.Loop() {
		if _, err := deflate(input); err != nil {
			b.Fatal(err)
		}
	}
}
