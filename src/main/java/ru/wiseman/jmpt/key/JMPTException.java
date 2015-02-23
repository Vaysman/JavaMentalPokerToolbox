package ru.wiseman.jmpt.key;

public class JMPTException extends RuntimeException {
    public JMPTException() {
        super();
    }

    public JMPTException(String message) {
        super(message);
    }

    public JMPTException(String message, Throwable cause) {
        super(message, cause);
    }

    public JMPTException(Throwable cause) {
        super(cause);
    }

    protected JMPTException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
