package com.rbac.exception;

public class UserAlreadyExistException extends RuntimeException{

	/**
	 * 
	 */
	private static final long serialVersionUID = 9024001729117273446L;
	
	public UserAlreadyExistException(String message) {
		super(message);
	}
	

}
