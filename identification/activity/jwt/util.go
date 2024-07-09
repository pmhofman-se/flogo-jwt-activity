package jwt

import (
	"fmt"

	"github.com/project-flogo/core/data/coerce"
)

func ParseNumber(inval interface{}) (outval interface{}, err error) {
	// make sure to support both int64 and float64 values
	intVal, intErr := coerce.ToInt64(inval)
	fltVal, fltErr := coerce.ToFloat64(inval)
	if intErr != nil && fltErr != nil {
		err := fmt.Errorf("parse int error: %v / parse float error: %v", intErr.Error(), fltErr.Error())
		return intVal, err
	} else if intErr != nil && fltErr == nil {
		return fltVal, nil
	} else if intErr == nil && fltErr != nil {
		return intVal, nil
	} else {
		if float64(intVal) != fltVal {
			outval = fltVal
		} else {
			outval = intVal
		}
		return outval, err
	}
}
