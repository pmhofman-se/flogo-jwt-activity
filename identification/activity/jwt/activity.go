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

var activityLog = log.ChildLogger(log.RootLogger(), ACTIVITY_LOGGER)
var activityLogSign = log.ChildLogger(activityLog, ACTIVITY_LOGGER_SIGN)
var activityLogVerify = log.ChildLogger(activityLog, ACTIVITY_LOGGER_VERIFY)
var activityLogDecodeOnly = log.ChildLogger(activityLog, ACTIVITY_LOGGER_DECODE_ONLY)

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
	case MODE_SIGN:
		done, err = Sign(settingsSigningMethod, context)
	case MODE_VERIFY:
		done, err = Verify(settingsSigningMethod, context)
	case MODE_DECODE_ONLY:
		done, err = DecodeOnly(settingsSigningMethod, context)
	}
	return done, err
}

func DecodeOnly(settingsSigningMethod string, context activity.Context) (bool, error) {

	input := &Input{}
	err := context.GetInputObject(input)
	if err != nil {
		return false, err
	}

	inputJWTToken := input.DecodeJWTToken

	// Parse the token without verifying the signature
	token, _, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseUnverified(inputJWTToken, jwt.MapClaims{})
	if err != nil {
		activityLogDecodeOnly.Errorf("Error parsing JWT: %v", err)
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
					activityLogSign.Debugf("Header: %v", header)
					if header != nil && header["Name"] != nil && header["Type"] != nil {
						var headerVal interface{}
						if header["Type"].(string) == "String" {
							headerVal, err = coerce.ToString(additionalHeaders[header["Name"].(string)])
						} else {
							err = errors.Newf("unsupported type %v for %v", header["Type"], header["Name"])
						}
						if err != nil {
							activityLogSign.Errorf("coercion failed with error %v for %v (type %v) value %v", err, header["Name"], header["Type"], additionalHeaders[header["Name"].(string)])
						}
						activityLogSign.Debugf("Headerval: %v Err: %v", headerVal, err)
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
					activityLogSign.Debugf("Field: %v", field)
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
							activityLogSign.Errorf("coercion failed with error %v for %v (type %v) value %v", err, field["Name"], field["Type"], payloadFields[field["Name"].(string)])
						}
						activityLogSign.Debugf("Fieldval: %v Err: %v", fieldVal, err)
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
		activityLogSign.Debugf("using signing method: %v", settingsSigningMethod)
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
		activityLogSign.Errorf("error decoding base64 private key: %v", err)
		return false, err
	}

	var signKey interface{}
	switch settingsSigningMethod {
	case SIGNING_METHOD_ES256, SIGNING_METHOD_ES384, SIGNING_METHOD_ES512:
		signKey, err = jwt.ParseECPrivateKeyFromPEM(decodedPrivateKey)
	case SIGNING_METHOD_EdDSA:
		signKey, err = jwt.ParseEdPrivateKeyFromPEM(decodedPrivateKey)
	case SIGNING_METHOD_HS256, SIGNING_METHOD_HS384, SIGNING_METHOD_HS512:
		signKey, err = []byte(inputSecret), nil
	case SIGNING_METHOD_PS256, SIGNING_METHOD_PS384, SIGNING_METHOD_PS512:
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	case SIGNING_METHOD_RS256, SIGNING_METHOD_RS384, SIGNING_METHOD_RS512:
		signKey, err = jwt.ParseRSAPrivateKeyFromPEM(decodedPrivateKey)
	case SIGNING_METHOD_NONE:
		signKey, err = nil, nil
		activityLogSign.Debugf("We don't support signing method: %v. Neither does the Go jwt package!", settingsSigningMethod)
	default:
		signKey, err = nil, nil
		activityLogSign.Debugf("Unknown signing method: %v. We don't support it! Neither does the Go jwt package!", settingsSigningMethod)
	}
	if err != nil {
		activityLogSign.Errorf("error parsing %v private key [%v]: %v", settingsSigningMethod, decodedPrivateKey, err)
		return false, err
	}

	signedString, err := token.SignedString(signKey)
	if err != nil {
		activityLogSign.Errorf("error signing: %v", err)
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
		activityLogVerify.Debugf("using signing method: %v", settingsSigningMethod)
	}

	var decodedPublicKey []byte
	switch settingsSigningMethod {
	case SIGNING_METHOD_ES256, SIGNING_METHOD_ES384, SIGNING_METHOD_ES512, SIGNING_METHOD_EdDSA, SIGNING_METHOD_PS256, SIGNING_METHOD_PS384, SIGNING_METHOD_PS512, SIGNING_METHOD_RS256, SIGNING_METHOD_RS384, SIGNING_METHOD_RS512:
		decodedPublicKey, err = base64.StdEncoding.DecodeString(inputPublicKey)
		if err != nil {
			activityLogVerify.Errorf("error decoding %v public key input: %v", inputPublicKey, err)
			return false, err
		}
	case SIGNING_METHOD_HS256, SIGNING_METHOD_HS384, SIGNING_METHOD_HS512, SIGNING_METHOD_NONE:
		fallthrough
	default:
	}

	var verifyKey interface{}
	switch settingsSigningMethod {
	case SIGNING_METHOD_ES256, SIGNING_METHOD_ES384, SIGNING_METHOD_ES512:
		verifyKey, err = jwt.ParseECPublicKeyFromPEM(decodedPublicKey)
	case SIGNING_METHOD_EdDSA:
		verifyKey, err = jwt.ParseEdPublicKeyFromPEM(decodedPublicKey)
	case SIGNING_METHOD_PS256, SIGNING_METHOD_PS384, SIGNING_METHOD_PS512, SIGNING_METHOD_RS256, SIGNING_METHOD_RS384, SIGNING_METHOD_RS512:
		verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(decodedPublicKey)
	case SIGNING_METHOD_HS256, SIGNING_METHOD_HS384, SIGNING_METHOD_HS512:
		verifyKey, err = []byte(inputSecret), nil
	case SIGNING_METHOD_NONE:
		fallthrough
	default:
		verifyKey, err = "", nil
		activityLogVerify.Debugf("invalid signing method selected: %v", settingsSigningMethod)
	}
	if err != nil {
		activityLogVerify.Errorf("error parsing %v public key: %v", settingsSigningMethod, err)
		return false, err
	}

	token, err := jwt.Parse(inputJWTToken, func(jwtToken *jwt.Token) (interface{}, error) {
		var ok bool
		switch settingsSigningMethod {
		case SIGNING_METHOD_ES256, SIGNING_METHOD_ES384, SIGNING_METHOD_ES512:
			_, ok = jwtToken.Method.(*jwt.SigningMethodECDSA)
		case SIGNING_METHOD_EdDSA:
			_, ok = jwtToken.Method.(*jwt.SigningMethodEd25519)
		case SIGNING_METHOD_HS256, SIGNING_METHOD_HS384, SIGNING_METHOD_HS512:
			_, ok = jwtToken.Method.(*jwt.SigningMethodHMAC)
		case SIGNING_METHOD_PS256, SIGNING_METHOD_PS384, SIGNING_METHOD_PS512:
			_, ok = jwtToken.Method.(*jwt.SigningMethodRSAPSS)
		case SIGNING_METHOD_RS256, SIGNING_METHOD_RS384, SIGNING_METHOD_RS512:
			_, ok = jwtToken.Method.(*jwt.SigningMethodRSA)
		case SIGNING_METHOD_NONE:
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
		activityLogVerify.Debugf("verified token: %v error: %v", token, err)
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
