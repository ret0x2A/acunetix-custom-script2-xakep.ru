if (true) {
    // Обозначь в логе, что скрипт запустился
    ax.log(ax.LogLevelInfo, "[SSRF-CHECK] SSRF POST-body analyzer started");

    // Тебе потребуется тело запроса
    let req = scriptArg.http.request;
    let body = req.body || "";

    // Работать скрипт будет с POST-запросами. Но можно расширить на PATH,DELETE,etc.
    if (req.method.toUpperCase() === "POST" && body.length > 0) {

        // Тело лучше бы декодировать
        let decodedBody = "";
        try {
            decodedBody = decodeURIComponent(body);
        } catch (e) {
            decodedBody = body; // если не удалось декодировать, берём как есть
        }


        // В угоду универсальности, оставь в регулярке и URL-кодированный поиск
        let urlRegex = /((?:https?|ftp|file|dict|sftp|tftp|ldap|gopher|netdoc)(?:%3A|:)(?:%2F%2F|\/\/)[a-zA-Z0-9\.\-\_\:\%]+(?:\/[^\s]*)?)/gi;

        let matches = decodedBody.match(urlRegex) || [];

        ax.log(ax.LogLevelInfo, `[SSRF-CHECK] MATCHES: ${matches.join(", ")}`);

        if (matches.length > 0) {
            // Если найдены совпадения, добавь уязвимость
            scanState.addVuln({
                location: scriptArg.location,
                typeId: "custom.xml",
                http: scriptArg.http,
                details: `Potential SSRF parameter found in POST body: [code]${matches.join(", ")}[/code]`
            });
        }
    }
}
