package io.mosip.openg2p.mediator.exception;

public class BaseCheckedException extends Exception{

    public BaseCheckedException() {
    }

    public BaseCheckedException(String errorCode, String errorMessage) {
        super(errorCode + " --> " + errorMessage);
    }

    public BaseCheckedException(String errorCode, String errorMessage, Throwable rootCause) {
        super(errorCode + " --> " + errorMessage, rootCause);
    }
}
