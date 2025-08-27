if (true) {
    if (scriptArg.http.response.status == 200) {
        let respBody = scriptArg.http.response.body;
        let contentType = scriptArg.http.response.headers.get('Content-Type') || "";

        let glb = scanState.getGlobal('aaa');

        ax.log(ax.LogLevelInfo, `Global ${glb}`);
        if (!glb) {
            ax.log(ax.LogLevelInfo, `Set global: bbb`);
        scanState.setGlobal('aaa', 'bbb');
        }

        ax.log(ax.LogLevelInfo, `RESPONSE DATA ${JSON.stringify(scriptArg.http.response)}`);
        ax.log(ax.LogLevelInfo, `HTTP DATA ${JSON.stringify(scriptArg.http)}`);
        ax.log(ax.LogLevelInfo, `Content Type: ${contentType}`);

        ax.log(ax.LogLevelInfo, `HEADERS: ${scriptArg.http.response.headers.toString()}`);
        // Словарь регэкспов (улучшенные)
        const regexMap = {
            "username/login": /\b(user(name)?|login|db_user)\b\s*[:=\s]?\s*["']?([A-Za-z0-9._\-@]+)["']?/gi,
            "password": /\b(pass(word)?|pwd|db_pass|secret)\b\s*[:=\s]?\s*["']?([A-Za-z0-9._\-@]+)["']?/gi,
            "host": /\b(host|server|addr(ess)?|db_host)\b\s*[:=\s]?\s*["']?([A-Za-z0-9._\-@]+)["']?/gi
        };

    /** 
     * В html могут быть, как комментарии в стиле JS, так и HML
     * В JS только JS
     * CSS приведен для примера
     */
    let commentPatterns = [];
    if (contentType.includes("text/html")) {
            commentPatterns.push(/<!--([\s\S]*?)-->/g);
            commentPatterns.push(/\/\/(.*)/g);
            commentPatterns.push(/\/\*([\s\S]*?)\*\//g);
        } else if (contentType.includes("javascript")) {
            commentPatterns.push(/\/\/(.*)/g);
            commentPatterns.push(/\/\*([\s\S]*?)\*\//g);
        } else if (contentType.includes("css")) {
            commentPatterns.push(/\/\*([\s\S]*?)\*\//g);
        }


        // Собираем все совпадения в массив, чтобы вывести одной уязвимостью
        let findings = [];
        // Для начала найдем все комментарии. Если данные вне комментов, их вряд ли кто-о прятал...
        commentPatterns.forEach((pattern) => {
            let m;
        // Выполняем поиск внутри каждого комментария
            while ((m = pattern.exec(respBody)) !== null) {
                let comment = m[1];
            // Ищем все варианты, которые есть в объекте-словаре
                for (let [category, re] of Object.entries(regexMap)) {
                    let innerMatch;
                    while ((innerMatch = re.exec(comment)) !== null) {
                        findings.push(`[bold]${category}[/bold]: [i]${innerMatch[0]}[/i]`);
                    }
                }
            }
        });

        // Если что-то нашли — создаём один уязвимость
        if (findings.length > 0) {
        /**
         *  Хотлось бы сделать красивый вывод, но Acunetix не даст этого сделать
         *  Окунь экранирует тэги, а браузеру не интересны всякие \n
         */
            let details = "[p]Potentially sensitive data found in comments:[/p]";
            details += findings.map((f,i) => `[li]${i+1} ${f}[/li]`).join(" ");
            details += `[p]Important paragraph[/p]`

            // Дублирование информации в лог для истории
            ax.log(ax.LogLevelInfo, `Collected [ul]${findings.length}[/ul] potential issues`);

        /**
         * Добавление уязвимости:
         * location - ссылка на страницу, где нашлись данные
         * typeId - для кастомных скриптов всегда custom.xml
         * http - объект с инфой о запросе/ответе. Без него в отчете об ошибке
         *        не будет этой информации. В случае с чувствительными данными 
         *        это полезно, так как может потребоваться посмотреть вживую без
         *        дополнительных движений. Значение берем из контекста выолнения
         *        чекера scriptArg
         * details - то, что собрали на странице/в файле
         * */
            scanState.addVuln({
                location: scriptArg.location,
                typeId: 'custom.xml',
                http: scriptArg.http,
                details: details
            });
        }
    }
}
