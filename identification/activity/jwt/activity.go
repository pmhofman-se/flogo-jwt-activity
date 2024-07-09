package jwt

import (
	"encoding/base64"
	"sort"

	"github.com/golang-jwt/jwt/v5"
	"github.com/project-flogo/core/activity"
	"github.com/project-flogo/core/data/coerce"
	"github.com/project-flogo/core/data/metadata"
	"github.com/project-flogo/core/support/log"
	"gopkg.in/errgo.v2/fmt/errors"
)

func init() {
	_ = activity.Register(&JWTActivity{}, New)
}

var activityLog = log.ChildLogger(log.RootLogger(), "jwt-activity-jwtsign")

var activityMd = activity.ToMetadata(&Settings{}, &Input{}, &Output{})

func New(ctx activity.InitContext) (activity.Activity, error) {
	s := &Settings{}
	err := metadata.MapToStruct(ctx.Settings(), s, true)

	if err != nil {
		return nil, err
	}

	act := &JWTActivity{settings: s}
	return act, nil
}

func (a *JWTActivity) Metadata() *activity.Metadata {
	return activityMd
}

func (a *JWTActivity) Eval(context activity.Context) (done bool, err error) {

	settingsSigningMethod := a.settings.SigningMethod
	settingsMode := a.settings.Mode

	switch settingsMode {
	case "Sign":
		done, err = Sign(settingsSigningMethod, context)
	case "Verify":
		done, err = Verify(settingsSigningMethod, context)
	}
	return done, err
}

func Sign(settingsSigningMethod string, context activity.Context) (bool, error) {

	input := &Input{}
	err := context.GetInputObject(input)
	if err != nil {
		return false, err
	}

	inputAdditionalHeaders := input.AdditionalHeaders
	inputAdditionalHeaderNames := input.AdditionalHeaderNames
	if inputAdditionalHeaders != nil && inputAdditionalHeaderNames != nil {
		if inputAdditionalHeaderNames != nil {
			additionalHeaders, _ := coerce.ToObject(inputAdditionalHeaders)
			if additionalHeaders != nil {
				headers := make(map[string]interface{}, len(additionalHeaders))
				for _, v := range inputAdditionalHeaderNames {
					header, _ := coerce.ToObject(v)
					activityLog.Debugf("Header: %v", header)
					if header != nil && header["Name"] != nil && header["Type"] != nil {
						var headerVal interface{}
						if header["Type"].(string) == "String" {
							headerVal, err = coerce.ToString(additionalHeaders[header["Name"].(string)])
						} else {
							err = errors.Newf("unsupported type %v for %v", header["Type"], header["Name"])
						}
						if err != nil {
							activityLog.Errorf("coercion failed with error %v for %v (type %v) value %v", err, header["Name"], header["Type"], additionalHeaders[header["Name"].(string)])
						}
						activityLog.Debugf("Headerval: %v Err: %v", headerVal, err)
						headers[header["Name"].(string)] = headerVal
					}
				}
				inputAdditionalHeaders = headers
			}
		}
	}
	if err != nil {
		return false, err
	}

	/*
		aStr, _ := json.Marshal(inputAdditionalHeaders)
		bStr, _ := json.Marshal(inputAdditionalHeaderNames)
		activityLog.Debugf("headers: %v header name: %v", string(aStr), string(bStr))
	*/

	inputPayloadFieldNames := input.PayloadFieldNames
	inputPayload := input.Payload
	if inputPayloadFieldNames != nil && inputPayload != nil {
		if inputPayloadFieldNames != nil {
			payloadFields, _ := coerce.ToObject(inputPayload)
			if payloadFields != nil {
				fields := make(map[string]interface{}, len(payloadFields))
				for _, v := range inputPayloadFieldNames {
					field, _ := coerce.ToObject(v)
					activityLog.Debugf("Field: %v", field)
					if field != nil && field["Name"] != nil && field["Type"] != nil {
						var fieldVal interface{}
						if payloadFields[field["Name"].(string)] != nil {
							if field["Type"].(string) == "String" {
								fieldVal, err = coerce.ToString(payloadFields[field["Name"].(string)])
							} else if field["Type"].(string) == "Number" {
								fieldVal, err = ParseNumber(payloadFields[field["Name"].(string)])
							} else if field["Type"].(string) == "Object" {
								fieldVal, err = coerce.ToObject(payloadFields[field["Name"].(string)])
							} else if field["Type"].(string) == "Array" {
								fieldVal, err = coerce.ToArray(payloadFields[field["Name"].(string)])
							} else {
								err = errors.Newf("unsupported type %v for %v", field["Type"], field["Name"])
							}
						}
						if err != nil {
							activityLog.Errorf("coercion failed with error %v for %v (type %v) value %v", err, field["Name"], field["Type"], payloadFields[field["Name"].(string)])
						}
						activityLog.Debugf("Fieldval: %v Err: %v", fieldVal, err)
						fields[field["Name"].(string)] = fieldVal
					}
				}
				inputPayload = fields
			}
		}
	}
	if err != nil {
		return false, err
	}

	/*
		aStr, _ = json.Marshal(inputPayload)
		bStr, _ = json.Marshal(inputPayloadFieldNames)
		activityLog.Debugf("payload: %v payload field names: %v", string(aStr), string(bStr))
	*/

	inputPrivateKey := input.PrivateKey
	inputSecret := input.Secret

	signingMethod := jwt.GetSigningMethod(settingsSigningMethod)
	if signingMethod == nil {
		supportedSigningMethods := jwt.GetAlgorithms()
		sort.Strings(supportedSigningMethods)
		err := errors.Newf("invalid signing method: %s. Supported: %v", settingsSigningMethod, supportedSigningMethods)
		return false, err
	} else {
		activityLog.Debugf("using signing method: %v", settingsSigningMethod)
	}

	claims := jwt.MapClaims{}
	for k, v := range inputPayload {
		claims[k] = v
	}

	token := jwt.NewWithClaims(signingMethod, claims)

	for k, v := range inputAdditionalHeaders {
		token.Header[k] = v
	}

	decodedPrivateKey, err := base64.StdEncoding.DecodeString(inputPrivateKey)
	if err != nil {
		activityLog.Errorf("error decoding base64 private key: %v", err)
		return false, err
	}

	var signKey interface{}
	switch settingsSigningMethod {
	case "ES256", "ES384", "ES512":
		signKey, err = jwt.ParseECPrivateKeyFromPEM(decodedPrivateKey)
	case "EdDSA":
		signKey, err = jwt.ParseEdPrivateKeyFromPEM(decodedPrivateKey)
	case "HS256", "HS384", "HS512":
		signKey, err = []byte(inputSecret), nil
	case "PS256", "PS384", "PS512":
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	case "RS256", "RS384", "RS512":
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	case "none":
		signKey, err = nil, nil
		activityLog.Debugf("We don't support signing method: %v. Neither does the Go jwt package!", settingsSigningMethod)
	default:
		signKey, err = nil, nil
		activityLog.Debugf("Unknown signing method: %v. We don't support it! Neither does the Go jwt package!", settingsSigningMethod)
	}
	if err != nil {
		activityLog.Errorf("error parsing %v private key [%v]: %v", settingsSigningMethod, decodedPrivateKey, err)
		return false, err
	}

	signedString, err := token.SignedString(signKey)
	if err != nil {
		activityLog.Errorf("error signing: %v", err)
		return false, err
	}

	err = context.SetOutput("JWTToken", signedString)
	return true, err
}

func Verify(settingsSigningMethod string, context activity.Context) (bool, error) {
	input := &Input{}
	err := context.GetInputObject(input)
	if err != nil {
		return false, err
	}

	inputSecret := input.Secret
	inputPublicKey := input.PublicKey
	inputJWTToken := input.VerifyJWTToken

	signingMethod := jwt.GetSigningMethod(settingsSigningMethod)
	if signingMethod == nil {
		supportedSigningMethods := jwt.GetAlgorithms()
		sort.Strings(supportedSigningMethods)
		err := errors.Newf("invalid signing method: %s. Supported: %v", settingsSigningMethod, supportedSigningMethods)
		return false, err
	} else {
		activityLog.Debugf("using signing method: %v", settingsSigningMethod)
	}

	var decodedPublicKey []byte
	switch settingsSigningMethod {
	case "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512":
		decodedPublicKey, err = base64.StdEncoding.DecodeString(inputPublicKey)
		if err != nil {
			activityLog.Errorf("error decoding %v public key input: %v", inputPublicKey, err)
			return false, err
		}
	case "HS256", "HS384", "HS512", "none":
		fallthrough
	default:
	}

	var verifyKey interface{}
	switch settingsSigningMethod {
	case "ES256", "ES384", "ES512":
		verifyKey, err = jwt.ParseECPublicKeyFromPEM(decodedPublicKey)
	case "EdDSA":
		verifyKey, err = jwt.ParseEdPublicKeyFromPEM(decodedPublicKey)
	case "PS256", "PS384", "PS512", "RS256", "RS384", "RS512":
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	case "HS256", "HS384", "HS512":
		verifyKey, err = []byte(inputSecret), nil
	case "none":
		fallthrough
	default:
		verifyKey, err = "", nil
		activityLog.Debugf("invalid signing method selected: %v", settingsSigningMethod)
	}
	if err != nil {
		activityLog.Errorf("error parsing %v public key: %v", settingsSigningMethod, err)
		return false, err
	}

	token, err := jwt.Parse(inputJWTToken, func(jwtToken *jwt.Token) (interface{}, error) {
		var ok bool
		switch settingsSigningMethod {
		case "ES256", "ES384", "ES512":
			_, ok = jwtToken.Method.(*jwt.SigningMethodECDSA)
		case "EdDSA":
			_, ok = jwtToken.Method.(*jwt.SigningMethodEd25519)
		case "HS256", "HS384", "HS512":
			_, ok = jwtToken.Method.(*jwt.SigningMethodHMAC)
		case "PS256", "PS384", "PS512":
			_, ok = jwtToken.Method.(*jwt.SigningMethodRSAPSS)
		case "RS256", "RS384", "RS512":
			_, ok = jwtToken.Method.(*jwt.SigningMethodRSA)
		case "none":
			fallthrough
		default:
			ok = false
		}
		if !ok {
			return nil, errors.Newf("unexpected method: %s", jwtToken.Header["alg"])
		}
		return verifyKey, nil
	})
	if err != nil {
		activityLog.Debugf("verified token: %v error: %v", token, err)
		return false, err
	}

	outputHeaders := make(map[string]interface{})
	for k, v := range token.Header {
		outputHeaders[k] = v
	}
	err = context.SetOutput("OutputHeaders", outputHeaders)
	if err != nil {
		return false, err
	}

	outputPayload := make(map[string]interface{})
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		for k, v := range claims {
			outputPayload[k] = v
		}
	}
	err = context.SetOutput("OutputPayload", outputPayload)
	if err != nil {
		return false, err
	}

	return true, nil
}
