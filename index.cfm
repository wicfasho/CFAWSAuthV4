<cfscript>
    aws_auth = new AWSAuthv4("accessID","secretKey","region","bucket-uri.s3.amazonaws.com");
    get_img = aws_auth.getObject("/image/home-v7-banner-3## dsf we.jpg"); //e.g https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html

    if(get_img.statuscode == '200 OK')
        cfcontent( variable = toBinary(toBase64(get_img.filecontent)) type = get_img['responseheader']['Content-Type'] reset = true);
</cfscript>
