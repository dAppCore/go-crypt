package corecompat

import "errors"

const hexAlphabet = "0123456789abcdef"
const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var errInvalidBase64 = errors.New("invalid base64 encoding")

// HexEncode mirrors core.HexEncode for the pinned core module used by go-crypt.
func HexEncode(src []byte) string {
	dst := make([]byte, len(src)*2)
	for i, b := range src {
		dst[i*2] = hexAlphabet[b>>4]
		dst[i*2+1] = hexAlphabet[b&0x0f]
	}
	return string(dst)
}

// Base64Encode mirrors core.Base64Encode for standard padded base64.
func Base64Encode(src []byte) string {
	if len(src) == 0 {
		return ""
	}

	dst := make([]byte, ((len(src)+2)/3)*4)
	si, di := 0, 0
	for len(src)-si >= 3 {
		n := uint32(src[si])<<16 | uint32(src[si+1])<<8 | uint32(src[si+2])
		dst[di] = base64Alphabet[n>>18&0x3f]
		dst[di+1] = base64Alphabet[n>>12&0x3f]
		dst[di+2] = base64Alphabet[n>>6&0x3f]
		dst[di+3] = base64Alphabet[n&0x3f]
		si += 3
		di += 4
	}

	switch len(src) - si {
	case 1:
		n := uint32(src[si]) << 16
		dst[di] = base64Alphabet[n>>18&0x3f]
		dst[di+1] = base64Alphabet[n>>12&0x3f]
		dst[di+2] = '='
		dst[di+3] = '='
	case 2:
		n := uint32(src[si])<<16 | uint32(src[si+1])<<8
		dst[di] = base64Alphabet[n>>18&0x3f]
		dst[di+1] = base64Alphabet[n>>12&0x3f]
		dst[di+2] = base64Alphabet[n>>6&0x3f]
		dst[di+3] = '='
	}

	return string(dst)
}

// Base64Decode mirrors core.Base64Decode for standard padded base64.
func Base64Decode(s string) ([]byte, error) {
	if len(s) == 0 {
		return []byte{}, nil
	}
	if len(s)%4 != 0 {
		return nil, errInvalidBase64
	}

	padding := 0
	if s[len(s)-1] == '=' {
		padding++
		if s[len(s)-2] == '=' {
			padding++
		}
	}

	dst := make([]byte, len(s)/4*3-padding)
	di := 0
	for si := 0; si < len(s); si += 4 {
		c0, ok := base64Value(s[si])
		if !ok {
			return nil, errInvalidBase64
		}
		c1, ok := base64Value(s[si+1])
		if !ok {
			return nil, errInvalidBase64
		}

		c2, c3 := byte(0), byte(0)
		if s[si+2] == '=' {
			if si+4 != len(s) || s[si+3] != '=' {
				return nil, errInvalidBase64
			}
		} else {
			c2, ok = base64Value(s[si+2])
			if !ok {
				return nil, errInvalidBase64
			}
		}
		if s[si+3] == '=' {
			if si+4 != len(s) {
				return nil, errInvalidBase64
			}
		} else {
			c3, ok = base64Value(s[si+3])
			if !ok {
				return nil, errInvalidBase64
			}
		}

		n := uint32(c0)<<18 | uint32(c1)<<12 | uint32(c2)<<6 | uint32(c3)
		if di < len(dst) {
			dst[di] = byte(n >> 16)
			di++
		}
		if di < len(dst) {
			dst[di] = byte(n >> 8)
			di++
		}
		if di < len(dst) {
			dst[di] = byte(n)
			di++
		}
	}

	return dst, nil
}

func base64Value(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z':
		return c - 'A', true
	case c >= 'a' && c <= 'z':
		return c - 'a' + 26, true
	case c >= '0' && c <= '9':
		return c - '0' + 52, true
	case c == '+':
		return 62, true
	case c == '/':
		return 63, true
	default:
		return 0, false
	}
}
