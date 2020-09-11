// get id_token expiry in seconds
var idTokenExpiryInSeconds = context.getVariable('jwt.VJ-VerifyIdPIssuedIdToken.seconds_remaining'); 
// set access_token expiry in milliseconds
var accessTokenExpiryInMilliSeconds = parseInt(idTokenExpiryInSeconds, 10) * 1000;
// set access_token expiry as a string in 'flow.idp.expires_in' variable
context.setVariable('flow.idp.expires_in',accessTokenExpiryInMilliSeconds.toString(10));
