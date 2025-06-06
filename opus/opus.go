package opus

import (
	"fmt"
	"unsafe"
)

/*
#cgo pkg-config: opus
#include <opus.h>

int opus_encoder_reset(OpusEncoder *st) {
    return opus_encoder_ctl(st, OPUS_RESET_STATE);
}

int opus_decoder_reset(OpusDecoder *st) {
    return opus_decoder_ctl(st, OPUS_RESET_STATE);
}
*/
import "C"

type Error C.int

func (err Error) Error() string {
	return fmt.Sprintf("libopus: %v",
		C.GoString(C.opus_strerror(C.int(err))),
	)
}

type Decoder struct {
	decoder        *C.OpusDecoder
	rate, channels int
}

func NewDecoder(rate int, channels int) (*Decoder, error) {
	var error C.int
	decoder := C.opus_decoder_create(
		C.opus_int32(rate),
		C.int(channels),
		&error,
	)
	if decoder == nil {
		return nil, Error(error)
	}
	return &Decoder{
		decoder:  decoder,
		rate:     rate,
		channels: channels,
	}, nil
}

func (decoder *Decoder) Destroy() {
	C.opus_decoder_destroy(decoder.decoder)
	decoder.decoder = nil
}

func (decoder *Decoder) Decode(data []byte, pcm []int16, fec bool) (int, error) {
	fecflag := C.int(0)
	if fec {
		fecflag = C.int(1)
	}

	rc := C.opus_decode(
		decoder.decoder,
		(*C.uchar)(unsafe.SliceData(data)),
		C.opus_int32(len(data)),
		(*C.opus_int16)(unsafe.SliceData(pcm)),
		C.int(len(pcm)/decoder.channels),
		fecflag,
	)
	if rc < 0 {
		return 0, Error(rc)
	}
	return int(rc)*decoder.channels, nil
}

func (decoder *Decoder) DecodeFloat(data []byte, pcm []float32, fec bool) (int, error) {
	fecflag := C.int(0)
	if fec {
		fecflag = C.int(1)
	}

	rc := C.opus_decode_float(
		decoder.decoder,
		(*C.uchar)(unsafe.SliceData(data)),
		C.opus_int32(len(data)),
		(*C.float)(unsafe.SliceData(pcm)),
		C.int(len(pcm)/decoder.channels),
		fecflag,
	)
	if rc < 0 {
		return 0, Error(rc)
	}
	return int(rc)*decoder.channels, nil
}

func (decoder *Decoder) Reset() error {
	rc := C.opus_decoder_reset(decoder.decoder)
	if rc < 0 {
		return Error(rc)
	}
	return nil
}

type Encoder struct {
	encoder        *C.OpusEncoder
	rate, channels int
}

func NewEncoder(rate int, channels int) (*Encoder, error) {
	var error C.int
	encoder := C.opus_encoder_create(
		C.opus_int32(rate),
		C.int(channels),
		C.OPUS_APPLICATION_VOIP,
		&error,
	)

	if encoder == nil {
		return nil, Error(error)
	}

	return &Encoder{
		encoder:  encoder,
		rate:     rate,
		channels: channels,
	}, nil
}

func (encoder *Encoder) Destroy() {
	C.opus_encoder_destroy(encoder.encoder)
	encoder.encoder = nil
}

func (encoder *Encoder) Encode(pcm []int16, data []byte) (int, error) {
	rc := C.opus_encode(
		encoder.encoder,
		(*C.opus_int16)(unsafe.Pointer(unsafe.SliceData(pcm))),
		C.int(len(pcm)/encoder.channels),
		(*C.uchar)(unsafe.SliceData(data)),
		C.opus_int32(len(data)),
	)
	if rc < 0 {
		return 0, Error(rc)
	}
	return int(rc), nil
}

func (encoder *Encoder) EncodeFloat(pcm []float32, data []byte) (int, error) {
	rc := C.opus_encode_float(
		encoder.encoder,
		(*C.float)(unsafe.Pointer(unsafe.SliceData(pcm))),
		C.int(len(pcm)/encoder.channels),
		(*C.uchar)(unsafe.SliceData(data)),
		C.opus_int32(len(data)),
	)
	if rc < 0 {
		return 0, Error(rc)
	}
	return int(rc), nil
}

func (encoder *Encoder) Reset() error {
	rc := C.opus_encoder_reset(encoder.encoder)
	if rc < 0 {
		return Error(rc)
	}
	return nil
}
