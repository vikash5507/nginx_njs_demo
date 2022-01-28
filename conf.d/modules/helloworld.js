function hello(r) {
    // ngx.log()
    ngx.log(ngx.ERR, r.variables.to);
    r.return(200, "Hello World Again!\n" + njs.version + "\n");
}

export default {hello}