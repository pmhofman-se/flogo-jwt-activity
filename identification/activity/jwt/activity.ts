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

interface DefaultValues {
    [key: string]: any;
}

interface ExampleInstance {
    [key: string]: any;
}

@WiContrib({})
@Injectable()
export class JWTActivityContribution extends WiServiceHandlerContribution {

    // Constants for field names
    private readonly FIELD_NAMES = {
        ADDITIONAL_HEADERS: 'AdditionalHeaders',
        ADDITIONAL_HEADER_NAMES: 'AdditionalHeaderNames',
        PAYLOAD: 'Payload',
        PAYLOAD_FIELD_NAMES: 'PayloadFieldNames',
        SECRET: 'Secret',
        OUTPUT_HEADERS: 'OutputHeaders',
        OUTPUT_HEADER_NAMES: 'OutputHeaderNames',
        OUTPUT_PAYLOAD: 'OutputPayload',
        OUTPUT_PAYLOAD_FIELD_NAMES: 'OutputPayloadFieldNames',
        SIGNING_METHOD: 'SigningMethod',
        MODE: 'Mode',
        PRIVATE_KEY: 'PrivateKey',
        PUBLIC_KEY: 'PublicKey',
        VERIFY_JWT_TOKEN: 'VerifyJWTToken',
        DECODE_JWT_TOKEN: 'DecodeJWTToken'
    } as const;

    private readonly SIGNING_METHODS_WITH_SECRET = ["HS256", "HS384", "HS512"];

    private readonly MODES = {
        SIGN: 'Sign',
        VERIFY: 'Verify',
        DECODE_ONLY: 'DecodeOnly'
    }

    constructor(@Inject(Injector) injector, private http: Http) {
        super(injector, http);
    }

    private getDefaultValueForType(type: string): any {
        const defaults: DefaultValues = {
            String: "abc",
            Number: 0.1,
            Boolean: false,
            Object: {},
            Array: []
        };
        return defaults[type] ?? null;
    }


    private generateDefaultValues(data: any): ExampleInstance {
        const defaults: ExampleInstance = {};
        for (const item of data) {
            defaults[item.Name] = this.getDefaultValueForType(item.Type);
        }
        return defaults;
    }

    value = (fieldName: string, context: IActivityContribution): Observable<any> | any => {
        if (fieldName === this.FIELD_NAMES.ADDITIONAL_HEADERS) {
            const additionalHeaderNames: IFieldDefinition = context.getField(this.FIELD_NAMES.ADDITIONAL_HEADER_NAMES);
            if (additionalHeaderNames.value) {
                const data = JSON.parse(additionalHeaderNames.value);
                const defaults = this.generateDefaultValues(data)
                return JSON.stringify(defaults);
            }
            return "{}";
        } else if (fieldName === this.FIELD_NAMES.PAYLOAD) {
            const payloadFieldNames: IFieldDefinition = context.getField(this.FIELD_NAMES.PAYLOAD_FIELD_NAMES);
            if (payloadFieldNames.value) {
                const data = JSON.parse(payloadFieldNames.value);
                const defaults = this.generateDefaultValues(data)
                return JSON.stringify(defaults);
            }
            return "{}";
        } else if (fieldName === this.FIELD_NAMES.SECRET) {
            return ""
        } else if (fieldName === this.FIELD_NAMES.OUTPUT_HEADERS) {
            const outputHeaderNames: IFieldDefinition = context.getField(this.FIELD_NAMES.OUTPUT_HEADER_NAMES);
            if (outputHeaderNames.value) {
                const data = JSON.parse(outputHeaderNames.value);
                const defaults = this.generateDefaultValues(data)
                return JSON.stringify(defaults);
            }
            return "{}";
        } else if (fieldName === this.FIELD_NAMES.OUTPUT_PAYLOAD) {
            const outputPayloadFieldNames: IFieldDefinition = context.getField(this.FIELD_NAMES.OUTPUT_PAYLOAD_FIELD_NAMES);
            if (outputPayloadFieldNames.value) {
                const data = JSON.parse(outputPayloadFieldNames.value);
                const defaults = this.generateDefaultValues(data)
                return JSON.stringify(defaults);
            }
            return "{}";
        }

        return null;
    }

    validate = (fieldName: string, context: IActivityContribution): Observable<IValidationResult> | IValidationResult => {
        if (fieldName === this.FIELD_NAMES.SIGNING_METHOD) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if (mode.value && (mode.value == this.MODES.SIGN || mode.value == this.MODES.VERIFY)) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === this.FIELD_NAMES.SECRET) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let signingMethod: IFieldDefinition = context.getField(this.FIELD_NAMES.SIGNING_METHOD)
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if ((mode.value && (mode.value == this.MODES.SIGN || mode.value == this.MODES.VERIFY)) &&
                (signingMethod.value && this.SIGNING_METHODS_WITH_SECRET.includes(signingMethod.value))) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === this.FIELD_NAMES.PRIVATE_KEY) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let signingMethod: IFieldDefinition = context.getField(this.FIELD_NAMES.SIGNING_METHOD)
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if ((mode.value && (mode.value == this.MODES.SIGN)) &&
                (signingMethod.value && !this.SIGNING_METHODS_WITH_SECRET.includes(signingMethod.value))) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === this.FIELD_NAMES.PUBLIC_KEY) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let signingMethod: IFieldDefinition = context.getField(this.FIELD_NAMES.SIGNING_METHOD)
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if ((mode.value && (mode.value == this.MODES.VERIFY)) &&
                (signingMethod.value && !this.SIGNING_METHODS_WITH_SECRET.includes(signingMethod.value))) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;
        }
        if (fieldName === this.FIELD_NAMES.VERIFY_JWT_TOKEN) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if (mode.value && (mode.value == this.MODES.VERIFY)) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
        if (fieldName === this.FIELD_NAMES.DECODE_JWT_TOKEN) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if (mode.value && (mode.value == this.MODES.DECODE_ONLY)) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
        if ((fieldName === this.FIELD_NAMES.ADDITIONAL_HEADERS) || 
            (fieldName === this.FIELD_NAMES.ADDITIONAL_HEADER_NAMES) || 
            (fieldName === this.FIELD_NAMES.PAYLOAD) || 
            (fieldName === this.FIELD_NAMES.PAYLOAD_FIELD_NAMES)) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if (mode.value && (mode.value == this.MODES.SIGN)) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
        if ((fieldName === this.FIELD_NAMES.OUTPUT_HEADERS) || 
            (fieldName === this.FIELD_NAMES.OUTPUT_HEADER_NAMES) || 
            (fieldName === this.FIELD_NAMES.PAYLOAD) || 
            (fieldName === this.FIELD_NAMES.PAYLOAD_FIELD_NAMES)) {
            let vresult: IValidationResult = ValidationResult.newValidationResult();
            let mode: IFieldDefinition = context.getField(this.FIELD_NAMES.MODE)
            if (mode.value && (mode.value == this.MODES.VERIFY || mode.value == this.MODES.DECODE_ONLY)) {
                vresult.setVisible(true);
            } else {
                vresult.setVisible(false);
            }
            return vresult;

        }
    }
}
