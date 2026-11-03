require("http").createServer((q,s)=>s.end("ok node")).listen(process.env.PORT||3000);
