function formatError(err) {
    if (!err) return "";
    if (err instanceof Error) {
        let msg = err.message || "";
        if (err.errors && Array.isArray(err.errors) && err.errors.length > 0) {
            const subMsgs = err.errors.map(e => e.message).join(', ');
            msg = msg ? `${msg} (${subMsgs})` : subMsgs;
        }
        return msg || err.toString();
    }
    if (typeof err === 'object') {
        return err.message || JSON.stringify(err);
    }
    return String(err);
}

function formatDetails(details) {
    if (!details) return {};
    const formatted = {};
    for (const key of Object.keys(details)) {
        const val = details[key];
        if (key === 'error' || val instanceof Error) {
            formatted[key] = formatError(val);
        } else {
            formatted[key] = val;
        }
    }
    return formatted;
}

const logger = {
    silent: false,
    info: (message, details = {}) => {
        if (logger.silent) return;
        console.log(JSON.stringify({ timestamp: new Date().toISOString(), level: 'INFO', message, ...formatDetails(details) }));
    },
    warn: (message, details = {}) => {
        if (logger.silent) return;
        console.warn(JSON.stringify({ timestamp: new Date().toISOString(), level: 'WARN', message, ...formatDetails(details) }));
    },
    error: (message, details = {}) => {
        if (logger.silent) return;
        console.error(JSON.stringify({ timestamp: new Date().toISOString(), level: 'ERROR', message, ...formatDetails(details) }));
    }
};

module.exports = logger;
