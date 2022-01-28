function stream_preread_verify(s) { //stream based authN
    var collect = '';
    
    s.on('upload', function (data, flags) {
        collect += data;
        ngx.log(ngx.ERR, collect);
        if(collect.length >= 5 && collect.startsWith('MAGiK')) {
            s.off('upload'); //unregisters the callback set by the s.on() method 

            //make remote call to AuthN service using ngx.fetch() which javascript Promise Object
            ngx.fetch('http://127.0.0.1:8080/validate', 
                {
                    body: collect.slice(5, 7),
                    headers: {
                        Host: 'aaa'
                    }
                })
                .then(reply =>  (reply.status == 200) ? s.done(): s.deny())
        } else if (collect.length) {
            s.deny();
        }
    })
}

function http_auth_validate(r) { //Mock Http AuthN Server, called by Stream
    return r.return((r.requestText == 'QZ') ? 200: 403);
}

export default {stream_preread_verify, http_auth_validate}