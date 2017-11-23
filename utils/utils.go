package utils

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	//	"github.com/davecgh/go-spew/spew"
	"reflect"
	"strings"
)

func Vcall(fi interface{}, callargs []interface{}) []reflect.Value {
	f := reflect.ValueOf(fi)
	args := []reflect.Value{}
	for _, val := range callargs {
		args = append(args, reflect.ValueOf(val))
	}
	return f.Call(args)
}

func Sdump(e interface{}) string {
	v := reflect.ValueOf(e)

	s := []string{}
	for i := 0; i < v.NumField(); i++ {
		s = append(s, fmt.Sprintf("%s: %s", v.Type().Field(i).Name, v.Field(i)))
	}

	return "{" + strings.Join(s, ", ") + "}"
}

func StringInSlice(s string, slice []string) bool {
	for _, i := range slice {
		if i == s {
			return true
		}
	}
	return false
}

func StringsInSlice(ss []string, slice []string) bool {
	for _, s := range ss {
		if e := StringInSlice(s, slice); e {
			return true
		}
	}
	return false
}

func SetFieldInStruct(t interface{}, field string, data interface{}) {
	s := reflect.ValueOf(t).Elem()
	switch data := data.(type) {
	default:
		log.Fatal("Unexpected type")
	case reflect.Value:
		s.FieldByName(field).Set(data)
	case string:
		s.FieldByName(field).SetString(data)
	case bool:
		s.FieldByName(field).SetBool(data)
	case []byte:
		s.FieldByName(field).SetBytes(data)
	case complex128:
		s.FieldByName(field).SetComplex(data)
	case float64:
		s.FieldByName(field).SetFloat(data)
	case int64:
		s.FieldByName(field).SetInt(data)
	}
}

func GetFieldInStruct(t interface{}, field string) interface{} {
	r := reflect.ValueOf(t)
	return reflect.Indirect(r).FieldByName(field)
}

func MergeSliceField(a interface{}, b interface{}, field string) {
	av := GetFieldInStruct(a, field).(reflect.Value)
	bv := GetFieldInStruct(b, field).(reflect.Value)
	av = reflect.AppendSlice(av, bv)
	SetFieldInStruct(b, field, av)
}
