package ru.wiseman.jmpt;

import ru.wiseman.jmpt.key.JMPTException;

public class ImportException extends JMPTException {
    public ImportException(String message) {
        super(message);
    }

    public ImportException(String message, Throwable cause) {
        super(message, cause);
    }
}
