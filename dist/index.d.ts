/// <reference types="aws-lambda" />
export declare const dictionary: {
    "aws:sns": {
        Records?: ({
            EventVersion?: string | undefined;
            EventSubscriptionArn?: string | undefined;
            EventSource?: string | undefined;
            Sns?: {
                SignatureVersion?: string | undefined;
                Timestamp?: string | undefined;
                Signature?: string | undefined;
                SigningCertUrl?: string | undefined;
                MessageId?: string | undefined;
                Message?: string | undefined;
                MessageAttributes?: {
                    [x: string]: {
                        Type?: string | undefined;
                        Value?: string | undefined;
                    } | undefined;
                } | undefined;
                Type?: string | undefined;
                UnsubscribeUrl?: string | undefined;
                TopicArn?: string | undefined;
                Subject?: string | undefined;
            } | undefined;
        } | undefined)[] | undefined;
    };
    "aws:sqs": {
        Records?: ({
            messageId?: string | undefined;
            receiptHandle?: string | undefined;
            body?: string | undefined;
            attributes?: {
                ApproximateReceiveCount?: string | undefined;
                SentTimestamp?: string | undefined;
                SenderId?: string | undefined;
                ApproximateFirstReceiveTimestamp?: string | undefined;
            } | undefined;
            messageAttributes?: {
                [x: string]: {
                    stringValue?: string | undefined;
                    binaryValue?: string | undefined;
                    stringListValues?: undefined[] | undefined;
                    binaryListValues?: undefined[] | undefined;
                    dataType?: string | undefined;
                } | undefined;
            } | undefined;
            md5OfBody?: string | undefined;
            eventSource?: string | undefined;
            eventSourceARN?: string | undefined;
            awsRegion?: string | undefined;
        } | undefined)[] | undefined;
    };
    "aws:apiGateway": {
        body?: string | null | undefined;
        headers?: {
            [x: string]: string | undefined;
        } | undefined;
        multiValueHeaders?: {
            [x: string]: (string | undefined)[] | undefined;
        } | undefined;
        httpMethod?: string | undefined;
        isBase64Encoded?: boolean | undefined;
        path?: string | undefined;
        pathParameters?: {
            [x: string]: string | undefined;
        } | null | undefined;
        queryStringParameters?: {
            [x: string]: string | undefined;
        } | null | undefined;
        multiValueQueryStringParameters?: {
            [x: string]: (string | undefined)[] | undefined;
        } | null | undefined;
        stageVariables?: {
            [x: string]: string | undefined;
        } | null | undefined;
        requestContext?: {
            accountId?: string | undefined;
            apiId?: string | undefined;
            authorizer?: {
                [x: string]: any;
            } | null | undefined;
            connectedAt?: number | undefined;
            connectionId?: string | undefined;
            domainName?: string | undefined;
            eventType?: string | undefined;
            extendedRequestId?: string | undefined;
            httpMethod?: string | undefined;
            identity?: {
                accessKey?: string | null | undefined;
                accountId?: string | null | undefined;
                apiKey?: string | null | undefined;
                apiKeyId?: string | null | undefined;
                caller?: string | null | undefined;
                cognitoAuthenticationProvider?: string | null | undefined;
                cognitoAuthenticationType?: string | null | undefined;
                cognitoIdentityId?: string | null | undefined;
                cognitoIdentityPoolId?: string | null | undefined;
                sourceIp?: string | undefined;
                user?: string | null | undefined;
                userAgent?: string | null | undefined;
                userArn?: string | null | undefined;
            } | undefined;
            messageDirection?: string | undefined;
            messageId?: string | null | undefined;
            path?: string | undefined;
            stage?: string | undefined;
            requestId?: string | undefined;
            requestTime?: string | undefined;
            requestTimeEpoch?: number | undefined;
            resourceId?: string | undefined;
            resourcePath?: string | undefined;
            routeKey?: string | undefined;
        } | undefined;
        resource?: string | undefined;
    };
    "aws:scheduled": {
        account?: string | undefined;
        region?: string | undefined;
        detail?: any;
        "detail-type"?: string | undefined;
        source?: string | undefined;
        time?: string | undefined;
        id?: string | undefined;
        resources?: (string | undefined)[] | undefined;
    };
    "aws:s3": {
        Records?: ({
            eventVersion?: string | undefined;
            eventSource?: string | undefined;
            awsRegion?: string | undefined;
            eventTime?: string | undefined;
            eventName?: string | undefined;
            userIdentity?: {
                principalId?: string | undefined;
            } | undefined;
            requestParameters?: {
                sourceIPAddress?: string | undefined;
            } | undefined;
            responseElements?: {
                'x-amz-request-id'?: string | undefined;
                'x-amz-id-2'?: string | undefined;
            } | undefined;
            s3?: {
                s3SchemaVersion?: string | undefined;
                configurationId?: string | undefined;
                bucket?: {
                    name?: string | undefined;
                    ownerIdentity?: {
                        principalId?: string | undefined;
                    } | undefined;
                    arn?: string | undefined;
                } | undefined;
                object?: {
                    key?: string | undefined;
                    size?: number | undefined;
                    eTag?: string | undefined;
                    versionId?: string | undefined;
                    sequencer?: string | undefined;
                } | undefined;
            } | undefined;
        } | undefined)[] | undefined;
    };
    "aws:kinesis": {
        Records?: ({
            awsRegion?: string | undefined;
            eventID?: string | undefined;
            eventName?: string | undefined;
            eventSource?: string | undefined;
            eventSourceARN?: string | undefined;
            eventVersion?: string | undefined;
            invokeIdentityArn?: string | undefined;
            kinesis?: {
                approximateArrivalTimestamp?: number | undefined;
                data?: string | undefined;
                kinesisSchemaVersion?: string | undefined;
                partitionKey?: string | undefined;
                sequenceNumber?: string | undefined;
            } | undefined;
        } | undefined)[] | undefined;
    };
    "aws:dynamo": {
        Records?: ({
            awsRegion?: string | undefined;
            dynamodb?: {
                ApproximateCreationDateTime?: number | undefined;
                Keys?: {
                    [x: string]: {
                        B?: string | undefined;
                        BS?: (string | undefined)[] | undefined;
                        BOOL?: boolean | undefined;
                        L?: (any | undefined)[] | undefined;
                        M?: {
                            [x: string]: any | undefined;
                        } | undefined;
                        N?: string | undefined;
                        NS?: (string | undefined)[] | undefined;
                        NULL?: boolean | undefined;
                        S?: string | undefined;
                        SS?: (string | undefined)[] | undefined;
                    } | undefined;
                } | undefined;
                NewImage?: {
                    [x: string]: {
                        B?: string | undefined;
                        BS?: (string | undefined)[] | undefined;
                        BOOL?: boolean | undefined;
                        L?: (any | undefined)[] | undefined;
                        M?: {
                            [x: string]: any | undefined;
                        } | undefined;
                        N?: string | undefined;
                        NS?: (string | undefined)[] | undefined;
                        NULL?: boolean | undefined;
                        S?: string | undefined;
                        SS?: (string | undefined)[] | undefined;
                    } | undefined;
                } | undefined;
                OldImage?: {
                    [x: string]: {
                        B?: string | undefined;
                        BS?: (string | undefined)[] | undefined;
                        BOOL?: boolean | undefined;
                        L?: (any | undefined)[] | undefined;
                        M?: {
                            [x: string]: any | undefined;
                        } | undefined;
                        N?: string | undefined;
                        NS?: (string | undefined)[] | undefined;
                        NULL?: boolean | undefined;
                        S?: string | undefined;
                        SS?: (string | undefined)[] | undefined;
                    } | undefined;
                } | undefined;
                SequenceNumber?: string | undefined;
                SizeBytes?: number | undefined;
                StreamViewType?: "KEYS_ONLY" | "NEW_IMAGE" | "OLD_IMAGE" | "NEW_AND_OLD_IMAGES" | undefined;
            } | undefined;
            eventID?: string | undefined;
            eventName?: "INSERT" | "MODIFY" | "REMOVE" | undefined;
            eventSource?: string | undefined;
            eventSourceARN?: string | undefined;
            eventVersion?: string | undefined;
            userIdentity?: any;
        } | undefined)[] | undefined;
    };
    "aws:cloudWatchLog": {
        awslogs?: {
            data?: string | undefined;
        } | undefined;
    };
    "aws:alexaSmartHome": {
        header?: {
            [x: string]: string | undefined;
        } | undefined;
        payload?: {
            switchControlAction?: string | undefined;
            appliance?: {
                additionalApplianceDetails?: {
                    [x: string]: string | undefined;
                } | undefined;
                applianceId?: string | undefined;
            } | undefined;
            accessToken?: string | undefined;
        } | undefined;
    };
    "aws:alexaSkill": {
        request?: {
            type?: string | undefined;
        } | undefined;
        version?: string | undefined;
        session?: {
            new?: boolean | undefined;
            sessionId?: string | undefined;
            application?: {
                applicationId?: string | undefined;
            } | undefined;
            attributes?: {
                [x: string]: string | undefined;
            } | undefined;
            user?: {
                userId?: string | undefined;
                accessToken?: string | undefined;
                permissions?: {
                    consentToken?: string | undefined;
                } | undefined;
            } | undefined;
        } | undefined;
        context?: {
            System?: {
                device?: {
                    deviceId?: string | undefined;
                    supportedInterfaces?: {
                        AudioPlayer?: any;
                    } | undefined;
                } | undefined;
                application?: {
                    applicationId?: string | undefined;
                } | undefined;
                user?: {
                    userId?: string | undefined;
                    accessToken?: string | undefined;
                    permissions?: {
                        consentToken?: string | undefined;
                    } | undefined;
                } | undefined;
                apiEndpoint?: string | undefined;
                apiAccessToken?: string | undefined;
            } | undefined;
            AudioPlayer?: {
                playerActivity?: string | undefined;
                token?: string | undefined;
                offsetInMilliseconds?: number | undefined;
            } | undefined;
        } | undefined;
    };
    "aws:cloudWatch": {
        version?: string | undefined;
        id?: string | undefined;
        "detail-type"?: string | undefined;
        source?: string | undefined;
        account?: string | undefined;
        time?: string | undefined;
        region?: string | undefined;
        resources?: (string | undefined)[] | undefined;
        detail?: {
            "instance-id"?: string | undefined;
            state?: string | undefined;
        } | undefined;
    };
    "aws:iot": any;
    "aws:cognitoUserPool": {
        version?: number | undefined;
        triggerSource?: "PreSignUp_SignUp" | "PostConfirmation_ConfirmSignUp" | "PreAuthentication_Authentication" | "PostAuthentication_Authentication" | "CustomMessage_SignUp" | "CustomMessage_AdminCreateUser" | "CustomMessage_ResendCode" | "CustomMessage_ForgotPassword" | "CustomMessage_UpdateUserAttribute" | "CustomMessage_VerifyUserAttribute" | "CustomMessage_Authentication" | "DefineAuthChallenge_Authentication" | "CreateAuthChallenge_Authentication" | "VerifyAuthChallengeResponse_Authentication" | "PreSignUp_AdminCreateUser" | "PostConfirmation_ConfirmForgotPassword" | "TokenGeneration_HostedAuth" | "TokenGeneration_Authentication" | "TokenGeneration_NewPasswordChallenge" | "TokenGeneration_AuthenticateDevice" | "TokenGeneration_RefreshTokens" | "UserMigration_Authentication" | "UserMigration_ForgotPassword" | undefined;
        region?: string | undefined;
        userPoolId?: string | undefined;
        userName?: string | undefined;
        callerContext?: {
            awsSdkVersion?: string | undefined;
            clientId?: string | undefined;
        } | undefined;
        request?: {
            userAttributes?: {
                [x: string]: string | undefined;
            } | undefined;
            validationData?: {
                [x: string]: string | undefined;
            } | undefined;
            codeParameter?: string | undefined;
            usernameParameter?: string | undefined;
            newDeviceUsed?: boolean | undefined;
            session?: ({
                challengeName?: "CUSTOM_CHALLENGE" | "PASSWORD_VERIFIER" | "SMS_MFA" | "DEVICE_SRP_AUTH" | "DEVICE_PASSWORD_VERIFIER" | "ADMIN_NO_SRP_AUTH" | undefined;
                challengeResult?: boolean | undefined;
                challengeMetadata?: string | undefined;
            } | undefined)[] | undefined;
            challengeName?: string | undefined;
            privateChallengeParameters?: {
                [x: string]: string | undefined;
            } | undefined;
            challengeAnswer?: string | undefined;
            password?: string | undefined;
        } | undefined;
        response?: {
            autoConfirmUser?: boolean | undefined;
            smsMessage?: string | undefined;
            emailMessage?: string | undefined;
            emailSubject?: string | undefined;
            challengeName?: string | undefined;
            issueTokens?: boolean | undefined;
            failAuthentication?: boolean | undefined;
            publicChallengeParameters?: {
                [x: string]: string | undefined;
            } | undefined;
            privateChallengeParameters?: {
                [x: string]: string | undefined;
            } | undefined;
            challengeMetadata?: string | undefined;
            answerCorrect?: boolean | undefined;
            userAttributes?: {
                [x: string]: string | undefined;
            } | undefined;
            finalUserStatus?: "CONFIRMED" | "RESET_REQUIRED" | undefined;
            messageAction?: "SUPPRESS" | undefined;
            desiredDeliveryMediums?: ("EMAIL" | "SMS" | undefined)[] | undefined;
            forceAliasCreation?: boolean | undefined;
        } | undefined;
    };
    "aws:websocket": {
        body?: string | null | undefined;
        headers?: {
            [x: string]: string | undefined;
        } | undefined;
        multiValueHeaders?: {
            [x: string]: (string | undefined)[] | undefined;
        } | undefined;
        httpMethod?: string | undefined;
        isBase64Encoded?: boolean | undefined;
        path?: string | undefined;
        pathParameters?: {
            [x: string]: string | undefined;
        } | null | undefined;
        queryStringParameters?: {
            [x: string]: string | undefined;
        } | null | undefined;
        multiValueQueryStringParameters?: {
            [x: string]: (string | undefined)[] | undefined;
        } | null | undefined;
        stageVariables?: {
            [x: string]: string | undefined;
        } | null | undefined;
        requestContext?: {
            accountId?: string | undefined;
            apiId?: string | undefined;
            authorizer?: {
                [x: string]: any;
            } | null | undefined;
            connectedAt?: number | undefined;
            connectionId?: string | undefined;
            domainName?: string | undefined;
            eventType?: string | undefined;
            extendedRequestId?: string | undefined;
            httpMethod?: string | undefined;
            identity?: {
                accessKey?: string | null | undefined;
                accountId?: string | null | undefined;
                apiKey?: string | null | undefined;
                apiKeyId?: string | null | undefined;
                caller?: string | null | undefined;
                cognitoAuthenticationProvider?: string | null | undefined;
                cognitoAuthenticationType?: string | null | undefined;
                cognitoIdentityId?: string | null | undefined;
                cognitoIdentityPoolId?: string | null | undefined;
                sourceIp?: string | undefined;
                user?: string | null | undefined;
                userAgent?: string | null | undefined;
                userArn?: string | null | undefined;
            } | undefined;
            messageDirection?: string | undefined;
            messageId?: string | null | undefined;
            path?: string | undefined;
            stage?: string | undefined;
            requestId?: string | undefined;
            requestTime?: string | undefined;
            requestTimeEpoch?: number | undefined;
            resourceId?: string | undefined;
            resourcePath?: string | undefined;
            routeKey?: string | undefined;
        } | undefined;
        resource?: string | undefined;
    };
};
export default function createEvent<T extends keyof typeof dictionary, B>(eventType: T, body: (typeof dictionary)[T]): (typeof dictionary)[T];
