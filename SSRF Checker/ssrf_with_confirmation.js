if (true) {
    
    const testAddreses = [
        "127.0.0.1",          // стандартный IPv4 loopback
        "127.1",              // сокращённая запись IPv4 loopback
        "127.0.1",            // альтернативная запись loopback
        "2130706433",         // десятичное представление 127.0.0.1
        "0x7f000001",         // шестнадцатеричное представление 127.0.0.1
        "017700000001",       // восьмеричное представление 127.0.0.1
        "0x7f.0.0.1",         // шестнадцатеричная точечная запись
        "0177.0.0.1",         // восьмеричная точечная запись
        "::1",                // IPv6 loopback
        "[::1]",              // IPv6 loopback с квадратными скобками (URL-форма)
        "::ffff:127.0.0.1",   // IPv4-mapped IPv6
        "localhost",          // hostname для loopback
        "ip6-localhost",      // IPv6 localhost
        "10.0.0.1",           // приватная сеть 10.0.0.0/8
        "10.255.255.255",     // верхняя граница диапазона 10.0.0.0/8
        "172.16.0.1",         // приватная сеть 172.16.0.0/12
        "172.31.255.255",     // верхняя граница диапазона 172.16.0.0/12
        "192.168.0.1",        // приватная сеть 192.168.0.0/16
        "192.168.1.1",        // типичный LAN IP
        "172.17.0.1",         // шлюз Docker bridge по умолчанию
        "10.96.0.1",          // сервис Kubernetes (часто используется)
        "10.96.0.10",         // Kubernetes DNS сервис (CoreDNS)
    ];

    const testPorts = [ null, 80, 8080, 8081 ];

    ax.log(ax.LogLevelInfo, "[SSRF-CHECK] SSRF POST-body analyzer started");

    let req = scriptArg.http.request;
    let res = scriptArg.http.response;
    let body = req.body || "";

    if (req.method.toUpperCase() === "POST" && body.length > 0) {
        let decodedBody = "";
        try {
            decodedBody = decodeURIComponent(body);
        } catch (e) {
            decodedBody = body;
        }

        let urlRegex = /((?:https?|ftp|file|dict|sftp|tftp|ldap|gopher|netdoc)(?:%3A|:)(?:%2F%2F|\/\/)[a-zA-Z0-9\.\-\_\:\%]+(?:\/[^\s]*)?)/gi;
        let matches = decodedBody.match(urlRegex) || [];

        ax.log(ax.LogLevelInfo, `[SSRF-CHECK] MATCHES: ${matches.join(", ")}`);

        if (matches.length > 0) {

            // Запоминаем «нормальную» длинну запроса
            let normalLength = res ? res.body.length : 0;

            // Пременная нужна, чтобы собрать все варианты адреса, которые прошли
            const confirmations = [];

            for (let match of matches) {

                for (let addr of testAddreses) {

                    for (let port of testPorts) {

                        // Если порт указан, добавляем в адрес
                        let testAddr = port ? `${addr}:${port}` : addr;

                        // Скопируй схему: http, ldap, etc...
                        let scheme = match.split("://")[0];
                        let testURL = scheme + "://" + testAddr;

                                // Создание нового http-задания и копирование свойств из существующего запроса
                        let job = ax.http.job();
                        job.hostname = scriptArg.http.hostname;
                        if (scriptArg.http.port) job.port = scriptArg.http.port;
                        job.secure = scriptArg.http.secure;
                        job.request.uri = req.uri;
                        job.request.method = "POST";

                        // Заголовки тоже стоит скопировать
                        if (req.headers) {
                            for (let h in req.headers) {
                                try { job.request.addHeader(h, req.headers[h]); } catch(e) {}
                            }
                        }               
                        
                        // Подмена инъекцией
                        job.request.body = decodedBody.replace(match, testURL)

                        ax.http.execute(job).sync();

                        if (!job.error) {
                            let testLength = job.response.body.length;
                            let testStatus = job.response.status;

                            ax.log(ax.LogLevelInfo, `[SSRF-CHECK] Response ${testStatus} (${testLength} bytes) for ${testURL}`);

                            let lengthDiff = Math.abs(testLength - normalLength);
                            let minDiff = testLength * 0.1

                            /**
                             * Если запрос успешный и разница в размере тела больше 10%, узвимость падает в список. 
                             * Не всегда нужно проверять на 200, зависит от таргета. Как и 10%, это просто тестовое значение
                             */
                            if (testStatus == 200 && lengthDiff > minDiff) {

                                // Сохранение объектом, чтобы записать ссылку на JOB и передать его в уязвимость. 
                                confirmations.push({text:`[li]${testURL} -> status [bold]${testStatus}[/bold], len=[bold]${testLength}[/bold] (diff=[bold]${lengthDiff})[/bold][/li]`, job});
                            } 
                        }
                    }
                }
            }

            let result = confirmations.map(el => el.text).join("")

            if (confirmations.length) {
                scanState.addVuln({
                    location: scriptArg.location,
                    typeId: "custom.xml",
                    http: confirmations[0].job,
                    details: `[p]Potential SSRF detected. Differing responses for test addresses:[/p] [ul]${result}[/ul]`
                });
            }
        }
    }
}
