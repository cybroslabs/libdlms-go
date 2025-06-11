package dlmsal

import (
	"fmt"
	"reflect"
	"time"
)

func Cast(trg any, data DlmsData) error {
	r := reflect.ValueOf(trg)
	if r.Kind() != reflect.Pointer || r.IsNil() {
		return fmt.Errorf("target must be a non-nil pointer")
	}
	return recast(reflect.Indirect(r), &data)
}

func recast(trg reflect.Value, data *DlmsData) error {
	e := trg.Kind()
	_, istime := trg.Interface().(time.Time)
	_, isdlmstime := trg.Interface().(DlmsDateTime)
	_, isobis := trg.Interface().(DlmsObis)
	_, isdlmsdata := trg.Interface().(DlmsData)
	_, isvalue := trg.Interface().(Value)
	if isdlmsdata {
		trg.Set(reflect.ValueOf(*data))
		return nil
	}
	if istime {
		switch b := data.Value.(type) {
		case []byte:
			if len(b) != 12 {
				return fmt.Errorf("invalid length")
			}
			bb, err := NewDlmsDateTimeFromSlice(b)
			if err != nil {
				return err
			}
			tt, err := bb.AsTime()
			if err != nil {
				return err
			}
			trg.Set(reflect.ValueOf(tt))
		case DlmsDateTime:
			tt, err := b.AsTime()
			if err != nil {
				return err
			}
			trg.Set(reflect.ValueOf(tt))
		default:
			return fmt.Errorf("invalid source type %T for time", b)
		}
		return nil
	}
	if isdlmstime {
		switch b := data.Value.(type) {
		case []byte:
			if len(b) != 12 {
				return fmt.Errorf("invalid length")
			}
			bb, err := NewDlmsDateTimeFromSlice(b)
			if err != nil {
				return err
			}
			trg.Set(reflect.ValueOf(bb))
		case DlmsDateTime:
			trg.Set(reflect.ValueOf(b))
		default:
			return fmt.Errorf("invalid source type %T for time", b)
		}
		return nil
	}
	if isobis {
		switch b := data.Value.(type) {
		case []byte:
			if len(b) != 6 {
				return fmt.Errorf("invalid length")
			}
			bb, err := NewDlmsObisFromSlice(b)
			if err != nil {
				return err
			}
			trg.Set(reflect.ValueOf(bb))
		default:
			return fmt.Errorf("invalid source type %T for obis", b)
		}
		return nil
	}
	if isvalue {
		return recastvalue(trg, data)
	}
	switch e {
	case reflect.Pointer:
		elem := reflect.New(trg.Type().Elem())
		err := recast(reflect.Indirect(elem), data)
		if err != nil {
			return err
		}
		trg.Set(elem)
	case reflect.Bool:
		return recastbool(trg, data)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return recastint(trg, data)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return recastuint(trg, data)
	case reflect.Float32, reflect.Float64:
		return recastfloat(trg, data)
	case reflect.String:
		return recaststring(trg, data)
	case reflect.Slice:
		return recastslice(trg, data)
	case reflect.Struct:
		return recaststruct(trg, data)
	default:
		return fmt.Errorf("unsupported type %v", e)
	}
	return nil
}

func recaststruct(trg reflect.Value, data *DlmsData) error {
	switch v := data.Value.(type) {
	case []DlmsData:
		n := len(v)

		if trg.NumField() != n {
			return fmt.Errorf("struct has %d fields, but data has %d fields", trg.NumField(), n)
		}

		for i := range n {
			if trg.Type().Field(i).IsExported() { // fill only exported (public) fields
				field := trg.Field(i)
				if field.Kind() == reflect.Pointer {
					if v[i].Tag != TagNull && field.IsNil() {
						field.Set(reflect.New(field.Type().Elem()))
					}

					if v[i].Tag == TagNull && !field.IsNil() {
						field.Set(reflect.Zero(field.Type()))
					}
				} else if v[i].Tag == TagNull {
					return fmt.Errorf("field %s is not a pointer, but has null tag in data", trg.Type().Field(i).Name)
				}

				if v[i].Tag != TagNull {
					if err := recast(reflect.Indirect(field), &v[i]); err != nil {
						return fmt.Errorf("struct error in field %s: %w", trg.Type().Field(i).Name, err)
					}
				}
			}
		}
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}

func recastslice(trg reflect.Value, data *DlmsData) error {
	// somehow determine type of slice
	switch v := data.Value.(type) {
	case []byte:
		switch trg.Type() {
		case reflect.TypeOf([]byte{}):
			if trg.IsNil() || trg.Cap() < len(v) {
				trg.Set(reflect.MakeSlice(trg.Type(), len(v), len(v)))
			} else {
				trg.SetLen(len(v))
			}
			copy(trg.Bytes(), v) // or trg.SetBytes ?
		default:
			return fmt.Errorf("invalid target type: %v", trg.Type())
		}
	case []DlmsData:
		if trg.IsNil() || trg.Cap() < len(v) {
			trg.Set(reflect.MakeSlice(trg.Type(), len(v), len(v)))
		} else {
			trg.SetLen(len(v))
		}
		for i := range v {
			vv := trg.Index(i)
			if vv.Kind() == reflect.Pointer && vv.IsNil() {
				vv.Set(reflect.New(vv.Type().Elem()))
			}
			err := recast(reflect.Indirect(vv), &v[i])
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}

func recaststring(trg reflect.Value, data *DlmsData) error {
	switch v := data.Value.(type) {
	case string:
		trg.SetString(v)
		return nil
	case []DlmsData:
	case []byte:
		trg.SetString(string(v))
		return nil
	default:
		trg.SetString(fmt.Sprintf("%v", v)) // like really? ;)
		return nil
	}
	return fmt.Errorf("unexpected type %T", data.Value)
}

func recastvalue(trg reflect.Value, data *DlmsData) error {
	value := Value{Type: Unknown}
	switch v := data.Value.(type) { // Tag should be also considered
	case bool:
		value.Type = Boolean
		value.Value = v
	case int8:
		value.Type = SignedInt
		value.Value = int64(v)
	case int16:
		value.Type = SignedInt
		value.Value = int64(v)
	case int32:
		value.Type = SignedInt
		value.Value = int64(v)
	case int64:
		value.Type = SignedInt
		value.Value = v
	case uint8:
		value.Type = UnsignedInt
		value.Value = uint64(v)
	case uint16:
		value.Type = UnsignedInt
		value.Value = uint64(v)
	case uint32:
		value.Type = UnsignedInt
		value.Value = uint64(v)
	case uint64:
		value.Type = UnsignedInt
		value.Value = v
	case float32:
		value.Type = Real
		value.Value = float64(v)
	case float64:
		value.Type = Real
		value.Value = v
	case string:
		value.Type = String
		value.Value = v
	case []byte:
		if len(v) == 12 {
			d, err := NewDlmsDateTimeFromSlice(v)
			if err == nil {
				value.Type = DateTime
				value.Value = d
				break
			}
		}
		value.Type = String
		value.Value = string(v)
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	trg.Set(reflect.ValueOf(value))
	return nil
}

func recastint(trg reflect.Value, data *DlmsData) error {
	switch v := data.Value.(type) {
	case bool:
		if v {
			trg.SetInt(1)
		} else {
			trg.SetInt(0)
		}
	case int8:
		trg.SetInt(int64(v))
	case int16:
		trg.SetInt(int64(v))
	case int32:
		trg.SetInt(int64(v))
	case int64:
		trg.SetInt(v)
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}

func recastbool(trg reflect.Value, data *DlmsData) error {
	switch v := data.Value.(type) {
	case bool:
		trg.SetBool(v)
	case int8:
		trg.SetBool(v != 0)
	case int16:
		trg.SetBool(v != 0)
	case int32:
		trg.SetBool(v != 0)
	case int64:
		trg.SetBool(v != 0)
	case uint8:
		trg.SetBool(v != 0)
	case uint16:
		trg.SetBool(v != 0)
	case uint32:
		trg.SetBool(v != 0)
	case uint64:
		trg.SetBool(v != 0)
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}

func recastuint(trg reflect.Value, data *DlmsData) error {
	switch v := data.Value.(type) {
	case bool:
		if v {
			trg.SetUint(1)
		} else {
			trg.SetUint(0)
		}
	case uint8:
		trg.SetUint(uint64(v))
	case uint16:
		trg.SetUint(uint64(v))
	case uint32:
		trg.SetUint(uint64(v))
	case uint64:
		trg.SetUint(v)
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}

func recastfloat(trg reflect.Value, data *DlmsData) error {
	switch v := data.Value.(type) {
	case bool:
		if v {
			trg.SetFloat(1)
		} else {
			trg.SetFloat(0)
		}
	case float32:
		trg.SetFloat(float64(v))
	case float64:
		trg.SetFloat(v)
	case int8:
		trg.SetFloat(float64(v))
	case int16:
		trg.SetFloat(float64(v))
	case int32:
		trg.SetFloat(float64(v))
	case int64:
		trg.SetFloat(float64(v))
	default:
		return fmt.Errorf("unexpected type %T", v)
	}
	return nil
}
