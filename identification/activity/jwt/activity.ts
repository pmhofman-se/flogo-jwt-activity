/*
 * Copyright © 2017. TIBCO Software Inc.
 * This file is subject to the license terms contained
 * in the license file that is distributed with this file.
 */
import { Observable } from "rxjs/Observable";
import { Injectable, Injector, Inject } from "@angular/core";
import { Http } from "@angular/http";
import {
    WiContrib,
    WiServiceHandlerContribution,
    IValidationResult,
    ValidationResult,
    IFieldDefinition,
    IActivityContribution,
    IConnectorContribution,
    WiContributionUtils
} from "wi-studio/app/contrib/wi-contrib";

@WiContrib({})
@Injectable()
export class JWTActivityContribution extends WiServiceHandlerContribution {
    constructor( @Inject(Injector) injector, private http: Http) {
        super(injector, http);
    }

    value = (fieldName: string, context: IActivityContribution): Observable<any> | any => {
        if (fieldName === "AdditionalHeaders") {
            let additionalHeaderNames: IFieldDefinition = context.getField("AdditionalHeaderNames");
            if (additionalHeaderNames.value) {
                // Read message attrbutes and construct JSON schema on the fly for the activity input
                var jsonSchema = {};
                // Convert string value into JSON object
                let data = JSON.parse(additionalHeaderNames.value);
                for (var i = 0; i < data.length; i++) {
                    if (data[i].Type === "String") {
                        jsonSchema[data[i].Name] = "abc";
                    } else if (data[i].Type === "Number") {
                        jsonSchema[data[i].Name] = 0.1;
                    }
                }
                return JSON.stringify(jsonSchema);
            }
            return "{}";
        } else if (fieldName === "Payload") {
            let payloadFieldNames: IFieldDefinition = context.getField("PayloadFieldNames");
            if (payloadFieldNames.value) {
                // Read message attrbutes and construct JSON schema on the fly for the activity input
                var jsonSchema = {};
                // Convert string value into JSON object
                let data = JSON.parse(payloadFieldNames.value);
                for (var i = 0; i < data.length; i++) {
                    if (data[i].Type === "String") {
                        jsonSchema[data[i].Name] = "abc";
                    } else if (data[i].Type === "Number") {
                        jsonSchema[data[i].Name] = 0.0;
                    } else if (data[i].Type === "Object") {
                        jsonSchema[data[i].Name] = {};
                    } else if (data[i].Type === "Array") {
                        jsonSchema[data[i].Name] = [];
                    }
                }
                return JSON.stringify(jsonSchema);
            }
            return "{}";
        } else if (fieldName === "Secret") {
            return ""
        } else if (fieldName === "OutputHeaders") {
            let outputHeaderNames: IFieldDefinition = context.getField("OutputHeaderNames");
            if (outputHeaderNames.value) {
                // Read message attrbutes and construct JSON schema on the fly for the activity input
                var jsonSchema = {};
                // Convert string value into JSON object
                let data = JSON.parse(outputHeaderNames.value);
                for (var i = 0; i < data.length; i++) {
                    if (data[i].Type === "String") {
                        jsonSchema[data[i].Name] = "abc";
                    } else if (data[i].Type === "Number") {
                        jsonSchema[data[i].Name] = 0.1;
                    }
                }
                return JSON.stringify(jsonSchema);
            }
            return "{}";
        } else if (fieldName === "OutputPayload") {
            let outputPayloadFieldNames: IFieldDefinition = context.getField("OutputPayloadFieldNames");
            if (outputPayloadFieldNames.value) {
                // Read message attrbutes and construct JSON schema on the fly for the activity input
                var jsonSchema = {};
                // Convert string value into JSON object
                let data = JSON.parse(outputPayloadFieldNames.value);
                for (var i = 0; i < data.length; i++) {
                    if (data[i].Type === "String") {
                        jsonSchema[data[i].Name] = "abc";
                    } else if (data[i].Type === "Number") {
                        jsonSchema[data[i].Name] = 0.0;
                    } else if (data[i].Type === "Object") {
                        jsonSchema[data[i].Name] = {};
                    } else if (data[i].Type === "Array") {
                        jsonSchema[data[i].Name] = [];
                    }
                }
                return JSON.stringify(jsonSchema);
            }
            return "{}";
        } 

        return null;
    }

    validate = (fieldName: string, context: IActivityContribution): Observable<IValidationResult> | IValidationResult => {
        if (fieldName === "SigningMethod") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField("Mode")
            if (mode.value && (mode.value == "Sign" || mode.value == "Verify")) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === "Secret") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let signingMethod: IFieldDefinition = context.getField("SigningMethod")
            let mode: IFieldDefinition = context.getField("Mode")
            if ((mode.value && (mode.value == "Sign" || mode.value == "Verify")) &&
                (signingMethod.value && (signingMethod.value == "HS256" || signingMethod.value == "HS384" || signingMethod.value == "HS512"))) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === "PrivateKey") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let signingMethod: IFieldDefinition = context.getField("SigningMethod")
            let mode: IFieldDefinition = context.getField("Mode")
            if ((mode.value && (mode.value == "Sign")) && 
                (signingMethod.value && (signingMethod.value != "HS256" && signingMethod.value != "HS384" && signingMethod.value != "HS512"))) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === "PublicKey") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let signingMethod: IFieldDefinition = context.getField("SigningMethod")
            let mode: IFieldDefinition = context.getField("Mode")
            if ((mode.value && (mode.value == "Verify")) && 
               (signingMethod.value && (signingMethod.value != "HS256" && signingMethod.value != "HS384" && signingMethod.value != "HS512"))) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === "VerifyJWTToken") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField("Mode")
            if (mode.value && (mode.value == "Verify")) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
        if (fieldName === "DecodeJWTToken") {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField("Mode")
            if (mode.value && (mode.value == "DecodeOnly")) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
        if ((fieldName === "AdditionalHeaders") || (fieldName === "AdditionalHeaderNames") || (fieldName === "Payload") || (fieldName === "PayloadFieldNames")) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField("Mode")
            if (mode.value && (mode.value == "Sign")) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
        if ((fieldName === "OutputHeaders") || (fieldName === "OutputHeaderNames") || (fieldName === "OutputPayload") || (fieldName === "OutputPayloadFieldNames")) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField("Mode")
            if (mode.value && (mode.value == "Verify" || mode.value == "DecodeOnly")) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
    }
}
