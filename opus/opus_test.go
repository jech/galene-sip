package opus

import (
	"fmt"
	"math"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	for _, ch := range []int{1, 2} {
		t.Run(fmt.Sprintf("%vchannels", ch), func(t *testing.T) {
			encoder, err := NewEncoder(8000, ch)
			if err != nil {
				t.Fatalf("NewEncoder: %v", err)
			}
			pcm := make([]int16, 160*ch)
			for i := 0; i < 160; i++ {
				v := int16(
					math.Cos(float64(i)/420*2*math.Pi) *
						16384)
				if ch == 1 {
					pcm[i] = v
				} else {
					pcm[2*i] = v
					pcm[2*i+1] = v
				}
			}
			data := make([]byte, 2048)
			n, err := encoder.Encode(pcm, data)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			decoder, err := NewDecoder(8000, ch)
			if err != nil {
				t.Fatalf("NewDecoder: %v", err)
			}
			pcm2 := make([]int16, 2048)
			m, err := decoder.Decode(data[:n], pcm2, false)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if m != 160*ch {
				t.Fatalf("Expected %v, got %v", 160*ch, m)
			}
		})
	}
}

func TestEncodeDecodeFloat(t *testing.T) {
	for _, ch := range []int{1, 2} {
		t.Run(fmt.Sprintf("%vchannels", ch), func(t *testing.T) {
			encoder, err := NewEncoder(8000, ch)
			if err != nil {
				t.Fatalf("NewEncoder: %v", err)
			}
			pcm := make([]float32, 160*ch)
			for i := 0; i < 160; i++ {
				v := float32(
					math.Cos(float64(i) / 420 * 2 * math.Pi),
				)
				if ch == 1 {
					pcm[i] = v
				} else {
					pcm[2*i] = v
					pcm[2*i+1] = v
				}
			}
			data := make([]byte, 2048)
			n, err := encoder.EncodeFloat(pcm, data)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			decoder, err := NewDecoder(8000, ch)
			if err != nil {
				t.Fatalf("NewDecoder: %v", err)
			}
			pcm2 := make([]float32, 2048)
			m, err := decoder.DecodeFloat(data[:n], pcm2, false)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if m != 160*ch {
				t.Fatalf("Expected %v, got %v", 160*ch, m)
			}
		})
	}
}
