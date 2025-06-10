package main

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/zaf/g711"
)

// sadd performs saturating addition of s into d
func sadd(d, s []int16) {
	for i, v := range s {
		if i >= len(d) {
			return
		}
		w := int32(d[i]) + int32(v)
		if w >= 0x7FFF {
			w = 0x7FFF
		}
		if w < -0x8000 {
			w = -0x8000
		}
		d[i] = int16(w)
	}
}

type audioBuffer struct {
	mu  sync.Mutex
	ts  time.Time
	pcm []int16
}

func (audio *audioBuffer) Put(ts time.Time, pcm []int16) {
	audio.mu.Lock()
	defer audio.mu.Unlock()

	if audio.ts.Equal(time.Time{}) {
		audio.ts = ts
	}

	delta := int(ts.Sub(audio.ts) / (time.Second / 48000))
	if delta < 0 {
		// packet in the past
		if -delta >= len(pcm) {
			return
		}
		sadd(audio.pcm, pcm[-delta:])
		return
	}

	if delta > len(audio.pcm) {
		return
	}
	sadd(audio.pcm[delta:], pcm)
}

const (
	// must be more than 20ms (one packet)
	mixingDelay = 40 * time.Millisecond
)

func (audio *audioBuffer) Get(samples int) (time.Time, []int16) {
	pcm := make([]int16, samples)

	audio.mu.Lock()
	defer audio.mu.Unlock()

	if audio.ts.Equal(time.Time{}) {
		audio.ts = time.Now().Add(-mixingDelay - 5*time.Millisecond)
	}

	copy(pcm, audio.pcm)
	if samples > len(audio.pcm) {
		clear(audio.pcm)
	} else {
		copy(audio.pcm, audio.pcm[samples:])
		clear(audio.pcm[len(audio.pcm)-samples:])
	}
	ts := audio.ts
	audio.ts = ts.Add(time.Duration(samples) * (time.Second / 48000))
	return ts, pcm
}

func (audio *audioBuffer) Shift(ts time.Time) {
	audio.mu.Lock()
	defer audio.mu.Unlock()

	delta := int(ts.Sub(audio.ts) / (time.Second / 48000))
	if delta <= -len(audio.pcm) || delta >= len(audio.pcm) {
		clear(audio.pcm)
		audio.ts = ts
		return
	}

	if delta < 0 {
		copy(audio.pcm[-delta:], audio.pcm)
		clear(audio.pcm[:-delta])
	} else {
		copy(audio.pcm, audio.pcm[delta:])
		clear(audio.pcm[len(audio.pcm)-delta:])
	}
	audio.ts = ts
}

func decodeAudio(codec string, dst []int16, src []byte) (int, error) {
	if strings.EqualFold(codec, "PCMA") {
		for i, v := range src {
			dst[i] = g711.DecodeAlawFrame(v)
		}
		return len(src), nil
	} else if strings.EqualFold(codec, "PCMU") {
		for i, v := range src {
			dst[i] = g711.DecodeUlawFrame(v)
		}
		return len(src), nil
	}
	return 0, errors.New("unknown codec " + codec)
}

func encodeAudio(codec string, down int, dst []byte, src []int16) (int, error) {
	count := len(src) / down
	if strings.EqualFold(codec, "PCMA") {
		for i := 0; i < count; i++ {
			var v int32
			for j := 0; j < down; j++ {
				v += int32(src[i*down+j])
			}
			dst[i] = g711.EncodeAlawFrame(
				int16(v / int32(down)),
			)
		}
		return count, nil
	} else if strings.EqualFold(codec, "PCMU") {
		for i := 0; i < count; i++ {
			var v int32
			for j := 0; j < down; j++ {
				v += int32(src[i*down+j])
			}
			dst[i] = g711.EncodeUlawFrame(
				int16(v / int32(down)),
			)
		}
		return count, nil
	}
	return 0, errors.New("unknown codec " + codec)
}

func isSilence(pcm []int16) bool {
	if len(pcm) == 0 {
		return true
	}
	energy := 0
	for _, v := range pcm {
		energy += int(v) * int(v)
	}
	return energy <= len(pcm)
}
