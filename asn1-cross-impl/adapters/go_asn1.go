package main

import (
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type IntSET []int

type Seq1 struct {
	Name string `asn1:"ia5"`
	Ok   bool
}

type Set1 struct {
	F bool
	N int
}

type Req struct {
	ID    string          `json:"id"`
	Mode  string          `json:"mode"`
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
	Hex   string          `json:"hex"`
}

type Resp struct {
	ID         string `json:"id"`
	Hex        string `json:"hex,omitempty"`
	Accepted   bool   `json:"accepted,omitempty"`
	ValueRepr  string `json:"value_repr,omitempty"`
	Error      string `json:"error,omitempty"`
	RestLen    int    `json:"rest_len,omitempty"`
}

func hexBytes(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, " ", "")
	return hex.DecodeString(s)
}

func encodeValue(typ string, raw json.RawMessage) ([]byte, error) {
	switch typ {
	case "BOOLEAN":
		var v bool
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return asn1.Marshal(v)
	case "INTEGER":
		var v int64
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return asn1.Marshal(int(v))
	case "OCTET_STRING":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		b, err := hexBytes(s)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(b)
	case "BIT_STRING":
		var v struct {
			Hex    string `json:"hex"`
			Unused int    `json:"unused"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		b, err := hexBytes(v.Hex)
		if err != nil {
			return nil, err
		}
		bs := asn1.BitString{Bytes: b, BitLength: len(b)*8 - v.Unused}
		return asn1.Marshal(bs)
	case "OID":
		var v []int
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return asn1.Marshal(asn1.ObjectIdentifier(v))
	case "SEQ1":
		var v struct {
			Name string `json:"name"`
			Ok   bool   `json:"ok"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return asn1.Marshal(Seq1{Name: v.Name, Ok: v.Ok})
	case "SET1":
		var v struct {
			N int  `json:"n"`
			F bool `json:"f"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return asn1.MarshalWithParams(Set1{F: v.F, N: v.N}, "set")
	case "SETOF_INT":
		var v []int
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, err
		}
		return asn1.Marshal(IntSET(v))
	case "UTCTime":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		t, err := time.Parse("060102150405Z", s)
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(t)
	case "SEQUENCE":
		// empty sequence (DefSeq with all defaults omitted)
		return asn1.Marshal(struct{}{})
	case "GeneralizedTime":
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return nil, err
		}
		t, err := time.Parse("20060102150405.000000000Z", strings.TrimSuffix(s, "Z")+"Z")
		// fallback
		if err != nil {
			t, err = time.Parse("20060102150405Z", s)
		}
		if err != nil {
			return nil, err
		}
		return asn1.MarshalWithParams(t, "generalized")
	default:
		return nil, fmt.Errorf("unknown type %s", typ)
	}
}

func decodeValue(typ string, raw []byte) (string, int, error) {
	switch typ {
	case "BOOLEAN":
		var v bool
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		repr := "false"
		if v {
			repr = "true"
		}
		return repr, len(rest), nil
	case "INTEGER":
		var v int
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		return fmt.Sprintf("%d", v), len(rest), nil
	case "OCTET_STRING":
		var v []byte
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		return hex.EncodeToString(v), len(rest), nil
	case "BIT_STRING":
		var v asn1.BitString
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		unused := len(v.Bytes)*8 - v.BitLength
		return fmt.Sprintf("%s unused=%d", hex.EncodeToString(v.Bytes), unused), len(rest), nil
	case "OID":
		var v asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		parts := make([]string, len(v))
		for i, n := range v {
			parts[i] = fmt.Sprintf("%d", n)
		}
		return strings.Join(parts, "."), len(rest), nil
	case "SEQ1":
		var v Seq1
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		return fmt.Sprintf("name=%s ok=%v", v.Name, v.Ok), len(rest), nil
	case "SET1":
		var v Set1
		rest, err := asn1.UnmarshalWithParams(raw, &v, "set")
		if err != nil {
			return "", len(raw), err
		}
		return fmt.Sprintf("n=%d f=%v", v.N, v.F), len(rest), nil
	case "SETOF_INT":
		var v IntSET
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		parts := make([]string, len(v))
		for i, n := range v {
			parts[i] = fmt.Sprintf("%d", n)
		}
		return strings.Join(parts, ","), len(rest), nil
	case "UTCTime":
		var v time.Time
		rest, err := asn1.Unmarshal(raw, &v)
		if err != nil {
			return "", len(raw), err
		}
		return v.UTC().Format("20060102150405Z"), len(rest), nil
	case "GeneralizedTime":
		var v time.Time
		rest, err := asn1.UnmarshalWithParams(raw, &v, "generalized")
		if err != nil {
			return "", len(raw), err
		}
		return v.UTC().Format("20060102150405Z"), len(rest), nil
	default:
		return "", len(raw), fmt.Errorf("unknown type %s", typ)
	}
}

func main() {
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)
	for {
		var req Req
		if err := dec.Decode(&req); err != nil {
			return
		}
		resp := Resp{ID: req.ID}
		switch req.Mode {
		case "encode":
			b, err := encodeValue(req.Type, req.Value)
			if err != nil {
				resp.Error = err.Error()
			} else {
				resp.Hex = hex.EncodeToString(b)
			}
		case "decode":
			b, err := hexBytes(req.Hex)
			if err != nil {
				resp.Error = err.Error()
				resp.Accepted = false
			} else {
				repr, rest, err := decodeValue(req.Type, b)
				if err != nil {
					resp.Error = err.Error()
					resp.Accepted = false
				} else {
					resp.Accepted = true
					resp.ValueRepr = repr
					resp.RestLen = rest
				}
			}
		default:
			resp.Error = "unknown mode"
		}
		enc.Encode(resp)
	}
}
