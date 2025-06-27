package jwt

import (
	"github.com/project-flogo/core/data/coerce"
)

type JWTActivity struct {
	settings *Settings
}

type Settings struct {
	SigningMethod string `md:"SigningMethod"`
	Mode          string `md:"Mode"`
}

type Input struct {
	AdditionalHeaderNames []interface{}          `md:"AdditionalHeaderNames"`
	AdditionalHeaders     map[string]interface{} `md:"AdditionalHeaders"`
	PayloadFieldNames     []interface{}          `md:"PayloadFieldNames"`
	Payload               map[string]interface{} `md:"Payload"`
	Secret                string                 `md:"Secret"`
	PrivateKey            string                 `md:"PrivateKey"`
	PublicKey             string                 `md:"PublicKey"`
	VerifyJWTToken        string                 `md:"VerifyJWTToken"`
	DecodeJWTToken        string                 `md:"DecodeJWTToken"`
}

func (i *Input) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"AdditionalHeaderNames": i.AdditionalHeaderNames,
		"AdditionalHeaders":     i.AdditionalHeaders,
		"PayloadFieldNames":     i.PayloadFieldNames,
		"Payload":               i.Payload,
		"Secret":                i.Secret,
		"PrivateKey":            i.PrivateKey,
		"PublicKey":             i.PublicKey,
		"VerifyJWTToken":        i.VerifyJWTToken,
		"DecodeJWTToken":        i.DecodeJWTToken,
	}
}

func (i *Input) FromMap(values map[string]interface{}) error {
	var err error

	i.AdditionalHeaderNames, err = coerce.ToArray(values["AdditionalHeaderNames"])
	if err != nil {
		return err
	}

	i.AdditionalHeaders, err = coerce.ToObject(values["AdditionalHeaders"])
	if err != nil {
		return err
	}

	i.PayloadFieldNames, err = coerce.ToArray(values["PayloadFieldNames"])
	if err != nil {
		return err
	}

	i.Payload, err = coerce.ToObject(values["Payload"])
	if err != nil {
		return err
	}

	i.Secret, err = coerce.ToString(values["Secret"])
	if err != nil {
		return err
	}

	i.PrivateKey, err = coerce.ToString(values["PrivateKey"])
	if err != nil {
		return err
	}

	i.PublicKey, err = coerce.ToString(values["PublicKey"])
	if err != nil {
		return err
	}

	i.VerifyJWTToken, err = coerce.ToString(values["VerifyJWTToken"])
	if err != nil {
		return err
	}

	i.DecodeJWTToken, err = coerce.ToString(values["DecodeJWTToken"])
	if err != nil {
		return err
	}

	return nil

}

type Output struct {
	JWTToken                string                 `md:"JWTToken"`
	OutputHeaderNames       []interface{}          `md:"OutputHeaderNames"`
	OutputHeaders           map[string]interface{} `md:"OutputHeaders"`
	OutputPayloadFieldNames []interface{}          `md:"OutputPayloadFieldNames"`
	OutputPayload           map[string]interface{} `md:"OutputPayload"`
}

// ToMap conversion
func (o *Output) ToMap() map[string]interface{} {
	return map[string]interface{}{
		"JWTToken":                o.JWTToken,
		"OutputHeaderNames":       o.OutputHeaderNames,
		"OutputHeaders":           o.OutputHeaders,
		"OutputPayloadFieldNames": o.OutputPayloadFieldNames,
		"OutputPayload":           o.OutputPayload,
	}
}

// FromMap conversion
func (o *Output) FromMap(values map[string]interface{}) error {
	var err error

	o.JWTToken, err = coerce.ToString(values["JWTToken"])
	if err != nil {
		return err
	}

	o.OutputHeaderNames, err = coerce.ToArray(values["OutputHeaderNames"])
	if err != nil {
		return err
	}

	o.OutputHeaders, err = coerce.ToObject(values["OutputHeaders"])
	if err != nil {
		return err
	}

	o.OutputPayloadFieldNames, err = coerce.ToArray(values["OutputPayloadFieldNames"])
	if err != nil {
		return err
	}

	o.OutputPayload, err = coerce.ToObject(values["OutputPayload"])
	if err != nil {
		return err
	}

	return nil
}
