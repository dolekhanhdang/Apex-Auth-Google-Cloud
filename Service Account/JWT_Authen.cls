public class JWT_Authen {
	static public String GetAccessToken()
    {
            HttpRequest req = new HttpRequest();
            req.setEndpoint('https://accounts.google.com/o/oauth2/token');
            req.setMethod('POST');
            req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
            
            JSONGenerator header = JSON.createGenerator(true);
            header.writeStartObject();
            header.writeStringField('alg', 'RS256');
            header.writeStringField('typ', 'JWT');
            header.writeEndObject();        
            String header_set = header.getAsString();
            
            JSONGenerator claim = JSON.createGenerator(true);
            claim.writeStartObject();
            string exp =  String.valueOf(datetime.now().addHours(1).getTime()/1000);
            string iat =  String.valueOf(datetime.now().getTime()/1000);
        	//iss	 The email address of the service account.
            claim.writeStringField('iss', 'test-salesforce@spry-scope-404907.iam.gserviceaccount.com');
        
        	//scope	 A space-delimited list of the permissions that the application requests.
            claim.writeStringField('scope', 'https://www.googleapis.com/auth/script');
        
        	//aud    Always https://accounts.google.com/o/oauth2/token
            claim.writeStringField('aud', 'https://accounts.google.com/o/oauth2/token');
        
       		//The expiration time of the assertion, max 1 hour, in Unix
            claim.writeStringField('exp', exp);
        
        	//The time the assertion was issued, in Unix
            claim.writeStringField('iat', iat);
            claim.writeEndObject();        
            
            String claim_set = claim.getAsString();
            system.debug(claim_set);
            String payload = EncodingUtil.Base64Encode(Blob.valueOf(header_set)) + '.' + EncodingUtil.Base64Encode(Blob.valueOf(claim_set));
        	String encode_payload = payload.replaceAll('=','');
            encode_payload = EncodingUtil.urlEncode(encode_payload,'UTF-8');
        
            String private_key = 'A9acTyhId=';
            blob private_key_decode = EncodingUtil.base64Decode(private_key);
            
            
            String signature = EncodingUtil.base64Encode(Crypto.sign('RSA-SHA256', Blob.valueOf(encode_payload), private_key_decode));
            String JWT = payload + '.' + signature;
            JWT = JWT.replaceAll('=','');
            
            String grant_string= 'urn:ietf:params:oauth:grant-type:jwt-bearer';
            req.setBody('grant_type=' + EncodingUtil.urlEncode(grant_string, 'UTF-8') + '&assertion=' + EncodingUtil.urlEncode(JWT, 'UTF-8'));
            HttpResponse res = new http().send(req);
            String response_debug = res.getBody() +' '+ res.getStatusCode();
            System.debug('Response =' + response_debug );
         	if(res.getStatusCode() == 200) {
                Map<String,object> m = (Map<String,object>)JSON.deserializeUntyped(res.getbody());
            	String access_token =(String)m.get('access_token');
                return access_token;
            }
        	return null;
    }
}