import java.util.ArrayList;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The PasswordCheckerUtility class provides utility methods for checking the validity
 * and strength of passwords based on various criteria.
 */

public class PasswordCheckerUtility {
	
    /**
     * Compares two passwords and throws an Exception (UnmatchedException) if they do not match.
     *
     * @param password     first password.
     * @param passwordConfirm     The second password compared against the first.
     * @throws UnmatchedException     If  passwords do not match.
     */

	public static void comparePasswords(String password, String passwordConfirm) throws UnmatchedException {
		
		if(!password.equals(passwordConfirm)) {
			throw new UnmatchedException("Passwords do not match");
		}

		
	}
	
	/**
     * Compares two passwords and returns true or false if they do or don't match.
     *
     * @param password        The first password.
     * @param passwordReturn  The second password to be compared against the first.
     * @return true if matching, false if not. (Boolean)
     */
	
	public static boolean comparePasswordsWithReturn(String password, String passwordReturn) {
		
		return(password.equals(passwordReturn));
	}
	
	
	/**
     * Checks password length requirement, passwords must be 6 chars long.
     *
     * @param password  - The password to be checked for length.
     * @return true  - if password meets the minimum length requirement.
     * @throws LengthException - If password doesn't meet minimum length requirement.
     */
	
	public static boolean isValidLength(String password) throws LengthException{
		
		if(password.length() < 6) {
			throw new LengthException("The password must be at least 6 characters long");
		}
		
		return true;
	}
	
	/**
     * Checks if the password contains upper case character.
     *
     * @param password -- The password to be checked for the upper case alpha character requirement.
     * @return true --  if password meets  upper case alpha character requirement.
     * @throws NoUpperAlphaException -- If password does not meet upper case alpha character requirement.
     */
	
	public static boolean hasUpperAlpha(String password) throws NoUpperAlphaException{
		if(!password.matches(".*[A-Z].*")) {
			throw new NoUpperAlphaException("Password doesn't have an uppercase character A-Z!");
		}
		return true;
	}
	
	/**
     * Checks if the password contains a lower case character.
     *
     * @param password -- The password to be checked.
     * @return true -- If the password meets the lower case character requirement.
     * @throws NoLowerAlphaException -- If the password does not meet the lower case character req.
     */
	
	public static boolean hasLowerAlpha(String password) throws NoLowerAlphaException {
		if(!password.matches(".*[a-z].*")) {
			throw new NoLowerAlphaException("The password must contain at least one lowercase alphabetic character");
		}
		return true;
	}
	
	/**
     * Checks if password contains a numeric character.
     *
     * @param password -- password to be checked for the numeric character.
     * @return true -- if password meets the numeric character requirement.
     * @throws NoDigitException -- If the password does not meet the numeric character requirement.
     */
	
	public static boolean hasDigit(String password) throws NoDigitException {
		if (!password.matches(".*\\d.*")) {
			throw new NoDigitException("Password must have a numerical digit 0-9.");
		}
		return true;
	}
	
	 /**
     * Checks whether password contains at least one special character.
     *
     * @param password -- The password to be checked for special character requirement.
     * @return true -- if the password satisfies special character requirement.
     * @throws NoSpecialCharacterException -- If the password lacks the necessary special character.
     */
	
	public static boolean hasSpecialChar(String password) throws NoSpecialCharacterException{
		
		if (!password.matches(".*[^A-Za-z0-9].*")) {
			throw new NoSpecialCharacterException("The password must contain at least one special character");
		}
		return true;
	}
	
	
	  /**
     * Verifies if password has two plus consecutive identical characters.
     *
     * @param password -- The password to be looked at for the consecutive identical characters.
     * @return false -- if the password doesn't have two or more consecutive identical characters.
     * @throws InvalidSequenceException -- If the password has two or more consecutive identical characters.
     */

	public static boolean NoSameCharInSequence(String password) throws InvalidSequenceException {
	        Pattern pattern = Pattern.compile("(\\w)\\1+");
	        Matcher matcher = pattern.matcher(password);

	        if (matcher.find()) {
	            throw new InvalidSequenceException("Password shouldn't have two of the same characters in sequence in a row.");
	        }

	        return false;
	    }
	
    /**
     * Validates a password for length, uppercase and lowercase letters,
     * digits, special characters, and consecutive same characters.
     *
     * @param message -- The password to be checked for validity.
     * @return true -- if the password meets all criteria, false otherwise.
     * @throws LengthException -- If the password length is less than 6 characters.
     * @throws NoUpperAlphaException -- If password lacks uppercase alphabetic character.
     * @throws NoLowerAlphaException -- If password lacks lowercase alphabetic character.
     * @throws NoDigitException -- If password lacks numeric digit.
     * @throws NoSpecialCharacterException -- If password lacks special character.
     * @throws InvalidSequenceException -- If password contains two or more consecutive identical characters.
     */
	
	public static boolean isValidPassword(String message) throws LengthException, NoUpperAlphaException,
	NoLowerAlphaException, NoDigitException, NoDigitException, NoSpecialCharacterException,InvalidSequenceException{
		
		return isValidLength(message) &&
			   hasUpperAlpha(message) &&
			   hasLowerAlpha(message) &&
			   hasDigit(message) &&
			   hasSpecialChar(message) &&
			   !NoSameCharInSequence(message);
			  		
	}
	
    /**
     * Checks if password has length of or is between 6 and 9 characters.
     *
     * @param password -- The password being checked.
     * @return true -- if password has length between 6 and 9 characters.
     */
	
	public static boolean hasBetweenSixAndNineChars(String password) {
		if(password.length()<=9 && password.length()>= 6) {
			return true;
		}
		return false;
	}
	
	 /**
     * Finds weak passwords based on their length.
     *
     * @param password -- The password being assessed.
     * @return false -- if password is valid and has a length longer than 9 characters.
     * @throws WeakPasswordException -- If password has a length between 6 and 9 characters.
     */
	
	public static boolean isWeakPassword(String password) throws WeakPasswordException{
		if(hasBetweenSixAndNineChars(password)) {
			throw new WeakPasswordException("Password is OK, but weak. Contains 9 or less characters.");
		}
		
		return false;
	}
	
	/**
	 * Gets invalid passwords from ArrayList of passwords.
	 * 
	 * @param passwords -- list of passwords to be checked
	 * @return invalidPasswords -- list of passwords deemed invalid based on numerous criteria.
	 */
	
	public static ArrayList<String> getInvalidPasswords(ArrayList<String> passwords) {
	    ArrayList<String> invalidPasswords = new ArrayList<>();

	    for (String password : passwords) {
	        try {
	            isValidPassword(password);
	        } catch (InvalidSequenceException | LengthException | NoDigitException |
	                NoLowerAlphaException | NoSpecialCharacterException | NoUpperAlphaException e) {
	            e.printStackTrace();

	            // Add a message to the invalid passwords list
	            invalidPasswords.add(password + " " + e.getMessage());
	        }
	    }

	    return invalidPasswords;
	}

	
}
