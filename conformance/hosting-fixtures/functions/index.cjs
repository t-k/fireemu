const {onRequest}=require('firebase-functions/v2/https');
exports.echo=onRequest((request,response)=>{
  response.setHeader('content-type','application/json');
  response.end(JSON.stringify({method:request.method,path:request.originalUrl,body:request.rawBody?.toString()??''}));
});
