component displayname="AWS Auth v4" hint="this component will initialize AWS Authv4 and allow retrieval of objects via the getObject method" {
    public AWSAuthv4 function init(
        required string accessID,
        required string secretKey,
        required string region,
        required string bucketURI
    ){
        variables.aws.accessID = arguments.accessID;
        variables.aws.secretKey = arguments.secretKey;;
        variables.aws.region = lcase(arguments.region);;
        variables.aws.bucketURI = arguments.bucketURI;

        local.datetime = dateConvert( "local2utc", now() );
        variables.aws.date = {
            "ONLYDATE": dateFormat( local.datetime, "YYYYMMdd"),
            "ISO8601": dateFormat( local.datetime, "YYYYMMdd" ) & "T" & timeFormat( local.datetime, "HHmmss" ) & "Z"
        };

        variables.aws.serviceName = "s3";
        variables.aws.algorithm = "HMACSHA256";

        return this;
    }

    private String function getSigningKey(){
        local.kSecret = charsetDecode("AWS4" & variables.aws.secretKey, "UTF-8")
        local.kDate = hmac(variables.aws.date.ONLYDATE, local.kSecret, variables.aws.algorithm); 
        local.kRegion = hmac(variables.aws.region, binaryDecode(local.kDate, "hex"), variables.aws.algorithm);
        local.kService = hmac(variables.aws.serviceName, binaryDecode(local.kRegion, "hex"), variables.aws.algorithm);
        local.kSigning = hmac("aws4_request", binaryDecode(local.kService, "hex"), variables.aws.algorithm);

        return lcase(local.kSigning);
    }

    private String function getSignatureKey(required string stringToSign){
        return lcase(hmac(arguments.StringToSign, binaryDecode(getSigningKey(), "hex"), variables.aws.algorithm));
    }

    private String function getAuthorizationCode(
        required string SignedHeaders,
        required string StringToSign
    ){
        return "AWS4-HMAC-SHA256 " & "Credential=" & variables.aws.accessID & "/" & variables.aws.date.ONLYDATE & "/" & variables.aws.region & "/" & variables.aws.serviceName & "/aws4_request" & ", SignedHeaders=" & arguments.SignedHeaders & ", Signature=" & getSignatureKey(arguments.StringToSign);
    }

    public Struct function getObject(required string object){
        local.newLine = chr(10);
        local.HTTPRequestMethod = "GET";

        // Encode Object URI
        local.CanonicalURI = arguments.object;
        local.CanonicalURI = local.CanonicalURI.listToArray("/");
        local.CanonicalURIEncoded = "";
        for(i in local.CanonicalURI){
            local.CanonicalURIEncoded &= "/" & encodeForURL(i).reReplaceNoCase("\+", "%20", "ALL")
        }
        local.CanonicalURI = local.CanonicalURIEncoded

        local.CanonicalQueryString = "";

        local.CanonicalHeaders = "host:" & trim(variables.aws.bucketURI) & local.newLine;
        local.CanonicalHeaders &= "x-amz-content-sha256:" & trim(lcase(hash("","SHA-256"))) & local.newLine;
        local.CanonicalHeaders &= "x-amz-date:" & trim(variables.aws.date.ISO8601) & local.newLine;

        local.SignedHeaders = "host;x-amz-content-sha256;x-amz-date";
        local.RequestPayload = lcase(hash("","SHA-256"));

        // Create Canonical Request
        local.CanonicalRequest = local.HTTPRequestMethod & local.newLine;
        local.CanonicalRequest &= local.CanonicalURI & local.newLine;
        local.CanonicalRequest &= local.CanonicalQueryString & local.newLine;
        local.CanonicalRequest &= local.CanonicalHeaders & local.newLine;
        local.CanonicalRequest &= local.SignedHeaders & local.newLine;
        local.CanonicalRequest &= local.RequestPayload;

        // Create String to Sign
        local.StringToSign = "AWS4-HMAC-SHA256" & local.newLine;
        local.StringToSign &= variables.aws.date.ISO8601 & local.newLine;
        local.StringToSign &= variables.aws.date.ONLYDATE & "/" & variables.aws.region & "/" & variables.aws.serviceName & "/aws4_request" & local.newLine;;
        local.StringToSign &= lcase(hash(local.CanonicalRequest, "SHA-256"));

        authorizationCode = getAuthorizationCode(
            local.SignedHeaders,
            local.StringToSign
        )

        local.url = variables.aws.bucketURI & local.CanonicalURI;
        cfhttp(url="#local.url#", method="GET", result="result" timeout="60") {
            cfhttpparam(type="header", name="Authorization", value=authorizationCode);
            cfhttpparam(type="header", name="host", value=trim(variables.aws.bucketURI));
            cfhttpparam(type="header", name="x-amz-content-sha256", value=trim(lcase(hash("","SHA-256"))));
            cfhttpparam(type="header", name="x-amz-date", value=trim(variables.aws.date.ISO8601));
        }

        return result;
    }
}
