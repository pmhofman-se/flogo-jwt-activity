package jwt

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/project-flogo/core/activity"
	"github.com/project-flogo/core/data/coerce"
	"github.com/project-flogo/core/support/test"
	"github.com/stretchr/testify/assert"
)

const (
	KEYS_BASE_PATH = "../../../testdata/"
)

func getKeyPath(signingMethod string) string {
	switch signingMethod {
	case "ES256":
		return KEYS_BASE_PATH + "ecdsa/es256/"
	case "ES384":
		return KEYS_BASE_PATH + "ecdsa/es384/"
	case "ES512":
		return KEYS_BASE_PATH + "ecdsa/es512/"
	case "EdDSA":
		return KEYS_BASE_PATH + "ed25519/"
	case "HS256", "HS384", "HS512":
		return KEYS_BASE_PATH + "secret/"
	case "PS256", "PS384", "PS512", "RS256", "RS384", "RS512":
		return KEYS_BASE_PATH + "rsa/"
	case "none":
		return ""
	default:
		return ""
	}
}

func readPrivateKey(signingMethod string, t *testing.T) ([]byte, error) {
	privateKeyFile, err := os.ReadFile(getKeyPath(signingMethod) + "private.pem")
	t.Logf("private key read:\n%v", string(privateKeyFile))
	return privateKeyFile, err
}

func readPublicKey(signingMethod string, t *testing.T) ([]byte, error) {
	publicKeyFile, err := os.ReadFile(getKeyPath(signingMethod) + "public.pem")
	t.Logf("public key read:\n%v", string(publicKeyFile))
	return publicKeyFile, err
}

func readKeyId(signingMethod string, t *testing.T) ([]byte, error) {
	publicKeyFile, err := os.ReadFile(getKeyPath(signingMethod) + "kid.txt")
	t.Logf("public key read:\n%v", string(publicKeyFile))
	return publicKeyFile, err
}

func readSecret(signingMethod string, t *testing.T) ([]byte, error) {
	publicKeyFile, err := os.ReadFile(getKeyPath(signingMethod) + "secret.txt")
	t.Logf("secret read:\n%v", string(publicKeyFile))
	return publicKeyFile, err
}

func createEmptyHeaderNames() []map[string]interface{} {
	return make([]map[string]interface{}, 0)
}

func createEmptyHeaders() map[string]interface{} {
	return make(map[string]interface{})
}

func createHeaderNamesWithUnsupportedType() []map[string]interface{} {
	ahn := make([]map[string]interface{}, 1)
	ahn[0] = map[string]interface{}{"Name": "dummy", "Type": "Dummy"}
	return ahn
}

func createHeadersWithUnsupportedType() map[string]interface{} {
	ah := make(map[string]interface{})
	ah["dummy"] = "nonsense"
	return ah
}

func createDrillsterHeaderNames() []map[string]interface{} {
	ahn := make([]map[string]interface{}, 1)
	ahn[0] = map[string]interface{}{"Name": "kid", "Type": "String"}
	return ahn
}

func createDrillsterHeaders(signingMethod string, t *testing.T) map[string]interface{} {
	keyIdFile, err := readKeyId(signingMethod, t)
	ah := make(map[string]interface{})
	if err != nil {
		t.Logf("error reading Key Id: %v. Key Id not added in headers.", err)
	} else {
		t.Logf("key id read:\n%v", string(keyIdFile))
		ah["kid"] = string(keyIdFile)
	}
	return ah
}

func createPayloadFieldNames() []map[string]interface{} {
	pfn := make([]map[string]interface{}, 5)
	pfn[0] = map[string]interface{}{"Name": "iss", "Type": "String"}
	pfn[1] = map[string]interface{}{"Name": "sub", "Type": "String"}
	pfn[2] = map[string]interface{}{"Name": "aud", "Type": "String"}
	pfn[3] = map[string]interface{}{"Name": "exp", "Type": "Number"}
	pfn[4] = map[string]interface{}{"Name": "iat", "Type": "Number"}
	return pfn
}

func createPayloadFieldNamesWithUnsupportedType() []map[string]interface{} {
	pfn := make([]map[string]interface{}, 1)
	pfn[0] = map[string]interface{}{"Name": "dummy", "Type": "Dummy"}
	return pfn
}

func createPayload() map[string]interface{} {
	p := make(map[string]interface{})
	p["aud"] = "some_audience"
	currentTime := time.Now().UTC().Unix()
	p["exp"] = currentTime + 3600
	p["iat"] = currentTime
	p["iss"] = "some_issuer"
	p["sub"] = "some_subject"
	return p
}

func createPayloadWithUnsupportedType() map[string]interface{} {
	p := make(map[string]interface{})
	p["dummy"] = "nonsense"
	return p
}

func createPayloadFieldNamesWithArray() []map[string]interface{} {
	pfn := make([]map[string]interface{}, 6)
	pfn[0] = map[string]interface{}{"Name": "iss", "Type": "String"}
	pfn[1] = map[string]interface{}{"Name": "sub", "Type": "String"}
	pfn[2] = map[string]interface{}{"Name": "aud", "Type": "String"}
	pfn[3] = map[string]interface{}{"Name": "exp", "Type": "Number"}
	pfn[4] = map[string]interface{}{"Name": "iat", "Type": "Number"}
	pfn[5] = map[string]interface{}{"Name": "array", "Type": "Array"}
	return pfn
}

func createPayloadWithArray() map[string]interface{} {
	p := make(map[string]interface{})
	p["aud"] = "some_audience"
	currentTime := time.Now().UTC().Unix()
	p["exp"] = currentTime + 3600
	p["iat"] = currentTime
	p["iss"] = "some_issuer"
	p["sub"] = "some_subject"
	arr := make([]map[string]interface{}, 2)
	arr[0] = map[string]interface{}{"element1": "data"}
	arr[1] = map[string]interface{}{"element2": "data"}
	p["array"] = arr
	return p
}

func createPayloadFieldNamesWithObject() []map[string]interface{} {
	pfn := make([]map[string]interface{}, 6)
	pfn[0] = map[string]interface{}{"Name": "iss", "Type": "String"}
	pfn[1] = map[string]interface{}{"Name": "sub", "Type": "String"}
	pfn[2] = map[string]interface{}{"Name": "aud", "Type": "String"}
	pfn[3] = map[string]interface{}{"Name": "exp", "Type": "Number"}
	pfn[4] = map[string]interface{}{"Name": "iat", "Type": "Number"}
	pfn[5] = map[string]interface{}{"Name": "object", "Type": "Object"}
	return pfn
}

func createPayloadWithObject() map[string]interface{} {
	p := make(map[string]interface{})
	p["aud"] = "some_audience"
	currentTime := time.Now().UTC().Unix()
	p["exp"] = currentTime + 3600
	p["iat"] = currentTime
	p["iss"] = "some_issuer"
	p["sub"] = "some_subject"
	obj := make(map[string]interface{})
	obj["field1"] = "data"
	obj["field2"] = "data"
	p["object"] = obj
	return p
}
func createDrillsterPayload() map[string]interface{} {
	p := make(map[string]interface{})
	p["aud"] = "https://www.drillster.com/daas/oauth/token"
	currentTime := time.Now().UTC().Unix()
	p["exp"] = currentTime + 3600
	p["iat"] = currentTime
	p["iss"] = "iqKpEF3URCe0yAsyrsk_4g"
	p["sub"] = "iqKpEF3URCe0yAsyrsk_4g"
	return p
}

func TestUtil_ParseNumber(t *testing.T) {
	v, err := ParseNumber("1")
	assert.Nil(t, err)
	assert.Equal(t, int64(1), v)

	v, err = ParseNumber("1234567890123456789012345678901234567890")
	assert.Nil(t, err)
	assert.Equal(t, float64(1.2345678901234568e+39), v)

	v, err = ParseNumber("1.1")
	assert.Nil(t, err)
	assert.Equal(t, float64(1.1), v)

	v, err = ParseNumber("a")
	assert.NotNil(t, err)
	assert.Equal(t, int64(0), v)
	expectedMsg := "parse int error: strconv.ParseInt: parsing \"a\": invalid syntax / parse float error: strconv.ParseFloat: parsing \"a\": invalid syntax"
	assert.EqualErrorf(t, err, expectedMsg, "Error should be: %v, got: %v", expectedMsg, err)
}

func TestMetaData(t *testing.T) {
	/*
		Set up activity Settings
	*/
	settingsSigningMethod := "none"
	settingsMode := "Sign"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		some tests only to increase coverage of metadata.go
	*/

	input := &Input{}
	err = tcSign.GetInputObject(input)
	assert.NotNil(t, input)
	assert.Nil(t, err)

	v := input.ToMap()
	assert.NotNil(t, v)

	v["AdditionalHeaderNames"] = 1
	err = input.FromMap(v)
	assert.Nil(t, err)

	v["AdditionalHeaders"] = 1
	err = input.FromMap(v)
	assert.NotNil(t, err)

	v = input.ToMap()
	v["Payload"] = 2
	err = input.FromMap(v)
	assert.NotNil(t, err)

	output := &Output{}
	err = tcSign.GetOutputObject(output)
	assert.NotNil(t, output)
	assert.Nil(t, err)

	v = output.ToMap()
	assert.NotNil(t, v)

	v["OutputHeaderNames"] = 3
	err = output.FromMap(v)
	assert.Nil(t, err)

	v["OutputHeaders"] = 3
	err = output.FromMap(v)
	assert.NotNil(t, err)

	v = output.ToMap()
	v["OutputPayload"] = 4
	err = output.FromMap(v)
	assert.NotNil(t, err)

	v = output.ToMap()
	assert.NotNil(t, v)
}

func TestRegister(t *testing.T) {

	ref := activity.GetRef(&JWTActivity{})
	act := activity.Get(ref)

	assert.NotNil(t, act)
}

func TestSign_none_Unsupported(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := "none"
	settingsMode := "Sign"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	additionalHeaderNames := createEmptyHeaderNames()
	tcSign.SetInput("AdditionalHeaderNames", additionalHeaderNames)

	additionalHeaders := createEmptyHeaders()
	tcSign.SetInput("AdditionalHeaders", additionalHeaders)

	payloadFieldNames := createPayloadFieldNames()
	tcSign.SetInput("PayloadFieldNames", payloadFieldNames)

	payload := createPayload()
	tcSign.SetInput("Payload", payload)
	tcSign.SetInput("PrivateKey", "")

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err, "error signing: token is unverifiable: 'none' signature type is not allowed")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func TestVerify_none_Unsupported(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := "none"
	settingsMode := "Verify"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	outputHeaderNames := createEmptyHeaderNames()
	_ = tcSign.SetOutput("OutputHeaderNames", outputHeaderNames)

	outputHeaders := createEmptyHeaders()
	_ = tcSign.SetOutput("OutputHeaders", outputHeaders)

	outputPayloadFieldNames := createPayloadFieldNames()
	_ = tcSign.SetOutput("OutputPayloadFieldNames", outputPayloadFieldNames)

	outputPayload := createPayload()
	tcSign.SetInput("OutputPayload", outputPayload)
	tcSign.SetInput("PublicKey", "")

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err, "error signing: token is unverifiable: 'none' signature type is not allowed")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func TestDecodeOnly_none_Unsupported(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := "none"
	settingsMode := "DecodeOnly"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	outputHeaderNames := createEmptyHeaderNames()
	_ = tcSign.SetOutput("OutputHeaderNames", outputHeaderNames)

	outputHeaders := createEmptyHeaders()
	_ = tcSign.SetOutput("OutputHeaders", outputHeaders)

	outputPayloadFieldNames := createPayloadFieldNames()
	_ = tcSign.SetOutput("OutputPayloadFieldNames", outputPayloadFieldNames)

	outputPayload := createPayload()
	tcSign.SetInput("OutputPayload", outputPayload)
	tcSign.SetInput("PublicKey", "")

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err, "error signing: token is unverifiable: 'none' signature type is not allowed")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func TestSign_NoSignMethod_Unsupported(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := ""
	settingsMode := "Sign"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	outputHeaderNames := createEmptyHeaderNames()
	_ = tcSign.SetOutput("OutputHeaderNames", outputHeaderNames)

	outputHeaders := createEmptyHeaders()
	_ = tcSign.SetOutput("OutputHeaders", outputHeaders)

	outputPayloadFieldNames := createPayloadFieldNames()
	_ = tcSign.SetOutput("OutputPayloadFieldNames", outputPayloadFieldNames)

	outputPayload := createPayload()
	tcSign.SetInput("OutputPayload", outputPayload)
	tcSign.SetInput("PublicKey", "")

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "invalid signing method: . Supported: [ES256 ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512 none]")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func TestVerify_NoSignMethod_Unsupported(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := ""
	settingsMode := "Verify"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	additionalHeaderNames := createEmptyHeaderNames()
	tcSign.SetInput("AdditionalHeaderNames", additionalHeaderNames)

	additionalHeaders := createEmptyHeaders()
	tcSign.SetInput("AdditionalHeaders", additionalHeaders)

	payloadFieldNames := createPayloadFieldNames()
	tcSign.SetInput("PayloadFieldNames", payloadFieldNames)

	payload := createPayload()
	tcSign.SetInput("Payload", payload)
	tcSign.SetInput("PrivateKey", "")

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "invalid signing method: . Supported: [ES256 ES384 ES512 EdDSA HS256 HS384 HS512 PS256 PS384 PS512 RS256 RS384 RS512 none]")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func TestJWTSign_UnsupportedHeaderType(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := "RS256"
	settingsMode := "Sign"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	additionalHeaderNames := createHeaderNamesWithUnsupportedType()
	tcSign.SetInput("AdditionalHeaderNames", additionalHeaderNames)

	additionalHeaders := createHeadersWithUnsupportedType()
	tcSign.SetInput("AdditionalHeaders", additionalHeaders)

	payloadFieldNames := createPayloadFieldNames()
	tcSign.SetInput("PayloadFieldNames", payloadFieldNames)

	payload := createPayload()
	tcSign.SetInput("Payload", payload)

	privateKeyFile, _ := readPrivateKey(settingsSigningMethod, t)
	base64PrivateKeyString := base64.StdEncoding.EncodeToString(privateKeyFile)
	tcSign.SetInput("PrivateKey", base64PrivateKeyString)

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "unsupported type Dummy for dummy")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func TestJWTSign_UnsupportedPayloadFieldType(t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := "RS256"
	settingsMode := "Sign"
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          settingsMode,
	}

	initContextSign := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContextSign)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	additionalHeaderNames := createEmptyHeaderNames()
	tcSign.SetInput("AdditionalHeaderNames", additionalHeaderNames)

	additionalHeaders := createEmptyHeaders()
	tcSign.SetInput("AdditionalHeaders", additionalHeaders)

	payloadFieldNames := createPayloadFieldNamesWithUnsupportedType()
	tcSign.SetInput("PayloadFieldNames", payloadFieldNames)

	payload := createPayloadWithUnsupportedType()
	tcSign.SetInput("Payload", payload)

	privateKeyFile, _ := readPrivateKey(settingsSigningMethod, t)
	base64PrivateKeyString := base64.StdEncoding.EncodeToString(privateKeyFile)
	tcSign.SetInput("PrivateKey", base64PrivateKeyString)

	done, err := actSign.Eval(tcSign)
	assert.NotNil(t, err)
	assert.EqualError(t, err, "unsupported type Dummy for dummy")
	assert.Equal(t, "", tcSign.GetOutput("JWTToken"))
	assert.False(t, done)
}

func SignAndVerifyTest(testSigningMethod string, additionalHeaderNames []map[string]interface{}, additionalHeaders map[string]interface{}, payloadFieldNames []map[string]interface{}, payload map[string]interface{}, t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := testSigningMethod
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          "Sign",
	}

	initContext := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContext)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	tcSign.SetInput("AdditionalHeaderNames", additionalHeaderNames)

	tcSign.SetInput("AdditionalHeaders", additionalHeaders)
	jsonInputHeaders, _ := json.Marshal(additionalHeaders)
	t.Logf("input headers:\n%v", string(jsonInputHeaders))

	tcSign.SetInput("PayloadFieldNames", payloadFieldNames)

	tcSign.SetInput("Payload", payload)
	jsonInputPayload, _ := json.Marshal(payload)
	t.Logf("input payload:\n%v", string(jsonInputPayload))

	switch settingsSigningMethod {
	case "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512":
		privateKeyFile, err := readPrivateKey(settingsSigningMethod, t)
		assert.Nil(t, err)
		base64PrivateKeyString := base64.StdEncoding.EncodeToString(privateKeyFile)
		t.Logf("private key base64 encoded:\n%v", base64PrivateKeyString)
		assert.NotEmpty(t, base64PrivateKeyString)

		tcSign.SetInput("PrivateKey", base64PrivateKeyString)
	case "HS256", "HS384", "HS512":
		secretFile, err := readSecret(settingsSigningMethod, t)
		assert.Nil(t, err)

		tcSign.SetInput("Secret", string(secretFile))
	case "none":
		fallthrough
	default:
	}

	/*
		Run activity
	*/
	doneSign, err := actSign.Eval(tcSign)
	assert.Nil(t, err)
	assert.True(t, doneSign)

	/*
		Collect the output
	*/
	generatedToken := tcSign.GetOutput("JWTToken")
	t.Logf("output token: %v", generatedToken)

	settingsVerify := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          "Verify",
	}
	initContextVerify := test.NewActivityInitContext(settingsVerify, nil)
	actVerify, err := New(initContextVerify)
	assert.Nil(t, err)

	tcVerify := test.NewActivityContext(actVerify.Metadata())

	/*
		Set the activity inputs for Verify
	*/

	tcVerify.SetInput("VerifyJWTToken", generatedToken)
	switch settingsSigningMethod {
	case "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512":
		publicKeyFile, err := readPublicKey(settingsSigningMethod, t)
		assert.Nil(t, err)
		base64PublicKeyString := base64.StdEncoding.EncodeToString(publicKeyFile)
		t.Logf("private key base64 encoded:\n%v", base64PublicKeyString)
		assert.NotEmpty(t, base64PublicKeyString)

		tcVerify.SetInput("PublicKey", base64PublicKeyString)
	case "HS256", "HS384", "HS512":
		secretFile, err := readSecret(settingsSigningMethod, t)
		assert.Nil(t, err)

		tcVerify.SetInput("Secret", string(secretFile))
	case "none":
		fallthrough
	default:
	}

	doneVerify, err := actVerify.Eval(tcVerify)
	assert.Nil(t, err)
	assert.True(t, doneVerify)

	outputHeaders, err := coerce.ToObject(tcVerify.GetOutput("OutputHeaders"))
	assert.Nil(t, err)
	assert.Equal(t, settingsSigningMethod, outputHeaders["alg"])
	assert.Equal(t, "JWT", outputHeaders["typ"])
	assert.Equal(t, 2+len(additionalHeaderNames), len(outputHeaders))
	jsonOutputHeaders, _ := json.Marshal(outputHeaders)
	t.Logf("output payload:\n%v", string(jsonOutputHeaders))

	outputPayload, err := coerce.ToObject(tcVerify.GetOutput("OutputPayload"))
	assert.Nil(t, err)
	assert.Equal(t, len(payload), len(outputPayload))
	for _, field := range payloadFieldNames {
		switch field["Type"].(string) {
		case "Number":
			numExpected, _ := ParseNumber(payload[field["Name"].(string)])
			numActual, _ := ParseNumber(outputPayload[field["Name"].(string)])
			assert.Equal(t, numExpected, numActual)
		case "Array":
			pl, _ := coerce.ToArray(payload[field["Name"].(string)])
			assert.Equal(t, pl, outputPayload[field["Name"].(string)])
		case "Object":
			pl, _ := coerce.ToObject(payload[field["Name"].(string)])
			assert.Equal(t, pl, outputPayload[field["Name"].(string)])
		default:
			assert.Equal(t, payload[field["Name"].(string)], outputPayload[field["Name"].(string)])
		}
	}
	jsonOutputPayload, _ := json.Marshal(outputPayload)
	t.Logf("output payload:\n%v", string(jsonOutputPayload))
}

func TestJWTSign_EdDSA(t *testing.T) {

	SignAndVerifyTest("EdDSA", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_HS256(t *testing.T) {

	SignAndVerifyTest("HS256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_HS384(t *testing.T) {

	SignAndVerifyTest("HS384", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_HS512(t *testing.T) {

	SignAndVerifyTest("HS512", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_ES256(t *testing.T) {

	SignAndVerifyTest("ES256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_ES384(t *testing.T) {

	SignAndVerifyTest("ES384", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_ES512(t *testing.T) {

	SignAndVerifyTest("ES512", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_PS256(t *testing.T) {

	SignAndVerifyTest("PS256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_PS384(t *testing.T) {

	SignAndVerifyTest("PS384", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_PS512(t *testing.T) {

	SignAndVerifyTest("PS512", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_RS256(t *testing.T) {

	SignAndVerifyTest("RS256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_RS384(t *testing.T) {

	SignAndVerifyTest("RS384", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_RS512(t *testing.T) {

	SignAndVerifyTest("RS512", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNames(), createPayload(), t)
}

func TestJWTSign_RS256_WithArray(t *testing.T) {

	SignAndVerifyTest("RS256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNamesWithArray(), createPayloadWithArray(), t)
}

func TestJWTSign_RS256_WithObject(t *testing.T) {

	SignAndVerifyTest("RS256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNamesWithObject(), createPayloadWithObject(), t)
}

func TestJWTSign_RSA256_Drillster(t *testing.T) {

	signingMethod := "RS256" // needed to get the file (kid.txt) with the key id for the Drillster specific header "kid"
	SignAndVerifyTest(signingMethod, createDrillsterHeaderNames(), createDrillsterHeaders(signingMethod, t), createPayloadFieldNames(), createDrillsterPayload(), t)
}

func SignAndDecodeOnlyTest(testSigningMethod string, additionalHeaderNames []map[string]interface{}, additionalHeaders map[string]interface{}, payloadFieldNames []map[string]interface{}, payload map[string]interface{}, t *testing.T) {

	/*
		Set up activity Settings
	*/
	settingsSigningMethod := testSigningMethod
	settingsSign := &Settings{
		SigningMethod: settingsSigningMethod,
		Mode:          "Sign",
	}

	initContext := test.NewActivityInitContext(settingsSign, nil)
	actSign, err := New(initContext)
	assert.Nil(t, err)

	tcSign := test.NewActivityContext(actSign.Metadata())

	/*
		Set the activity inputs
	*/
	tcSign.SetInput("AdditionalHeaderNames", additionalHeaderNames)

	tcSign.SetInput("AdditionalHeaders", additionalHeaders)
	jsonInputHeaders, _ := json.Marshal(additionalHeaders)
	t.Logf("input headers:\n%v", string(jsonInputHeaders))

	tcSign.SetInput("PayloadFieldNames", payloadFieldNames)

	tcSign.SetInput("Payload", payload)
	jsonInputPayload, _ := json.Marshal(payload)
	t.Logf("input payload:\n%v", string(jsonInputPayload))

	switch settingsSigningMethod {
	case "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512":
		privateKeyFile, err := readPrivateKey(settingsSigningMethod, t)
		assert.Nil(t, err)
		base64PrivateKeyString := base64.StdEncoding.EncodeToString(privateKeyFile)
		t.Logf("private key base64 encoded:\n%v", base64PrivateKeyString)
		assert.NotEmpty(t, base64PrivateKeyString)

		tcSign.SetInput("PrivateKey", base64PrivateKeyString)
	case "HS256", "HS384", "HS512":
		secretFile, err := readSecret(settingsSigningMethod, t)
		assert.Nil(t, err)

		tcSign.SetInput("Secret", string(secretFile))
	case "none":
		fallthrough
	default:
	}

	/*
		Run activity
	*/
	doneSign, err := actSign.Eval(tcSign)
	assert.Nil(t, err)
	assert.True(t, doneSign)

	/*
		Collect the output
	*/
	generatedToken := tcSign.GetOutput("JWTToken")
	t.Logf("output token: %v", generatedToken)

	settingsDecodeOnly := &Settings{
		Mode: "DecodeOnly",
	}
	initContextDecodeOnly := test.NewActivityInitContext(settingsDecodeOnly, nil)
	actDecodeOnly, err := New(initContextDecodeOnly)
	assert.Nil(t, err)

	tcDecodeOnly := test.NewActivityContext(actDecodeOnly.Metadata())

	/*
		Set the activity inputs for Verify
	*/

	tcDecodeOnly.SetInput("DecodeJWTToken", generatedToken)

	doneDecodeOnly, err := actDecodeOnly.Eval(tcDecodeOnly)
	assert.Nil(t, err)
	assert.True(t, doneDecodeOnly)

	outputHeaders, err := coerce.ToObject(tcDecodeOnly.GetOutput("OutputHeaders"))
	assert.Nil(t, err)
	assert.Equal(t, settingsSigningMethod, outputHeaders["alg"])
	assert.Equal(t, "JWT", outputHeaders["typ"])
	assert.Equal(t, 2+len(additionalHeaderNames), len(outputHeaders))
	jsonOutputHeaders, _ := json.Marshal(outputHeaders)
	t.Logf("output payload:\n%v", string(jsonOutputHeaders))

	outputPayload, err := coerce.ToObject(tcDecodeOnly.GetOutput("OutputPayload"))
	assert.Nil(t, err)
	assert.Equal(t, len(payload), len(outputPayload))
	for _, field := range payloadFieldNames {
		switch field["Type"].(string) {
		case "Number":
			numExpected, _ := ParseNumber(payload[field["Name"].(string)])
			numActual, _ := ParseNumber(outputPayload[field["Name"].(string)])
			assert.Equal(t, numExpected, numActual)
		case "Array":
			pl, _ := coerce.ToArray(payload[field["Name"].(string)])
			assert.Equal(t, pl, outputPayload[field["Name"].(string)])
		case "Object":
			pl, _ := coerce.ToObject(payload[field["Name"].(string)])
			assert.Equal(t, pl, outputPayload[field["Name"].(string)])
		default:
			assert.Equal(t, payload[field["Name"].(string)], outputPayload[field["Name"].(string)])
		}
	}
	jsonOutputPayload, _ := json.Marshal(outputPayload)
	t.Logf("output payload:\n%v", string(jsonOutputPayload))
}

func TestJWTSignAndDecode_RS256_WithObject(t *testing.T) {

	SignAndDecodeOnlyTest("RS256", createEmptyHeaderNames(), createEmptyHeaders(), createPayloadFieldNamesWithObject(), createPayloadWithObject(), t)
}
