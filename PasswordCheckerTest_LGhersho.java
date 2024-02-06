
import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * STUDENT tests for the methods of PasswordChecker
 * @author 
 *
 */
public class PasswordCheckerTest_LGhersho {

	private ArrayList<String> studentPasswords;

    @Before
    public void setUp() {
        studentPasswords = new ArrayList<>();
        studentPasswords.add("SoStrongPassword13@");
        studentPasswords.add("AnotherStrongPassword!1");
    }

    @After
    public void tearDown() {
        studentPasswords = null;
    }


    @Test
    public void testComparePasswordsPass() {
        try {
            PasswordCheckerUtility.comparePasswords("Liamisfuny12!", "Liamisfuny12!");
            // The test passes if no exception is thrown
        } catch (UnmatchedException e) {
            fail("UnmatchedException");
        }
    }

    @Test
    public void testComparePasswordsFail() {
        try {
            PasswordCheckerUtility.comparePasswords("Thisone132!", "Nothesame12@");
            fail("Expected UnmatchedException");
        } catch (UnmatchedException e) {
            assertEquals("Passwords do not match", e.getMessage());
        }
    }

    @Test
    public void testIsValidLengthPass() {
        for (String password : studentPasswords) {
            try {
                assertTrue(PasswordCheckerUtility.isValidLength(password));
            } catch (LengthException e) {
                fail("Unexpected LengthException");
            }
        }
    }

    @Test
    public void testIsValidLengthFail() {
        try {
            assertFalse(PasswordCheckerUtility.isValidLength("Weak"));
        } catch (LengthException e) {
            assertEquals("The password must be at least 6 characters long", e.getMessage());
        }
    }
    
    @Test
    public void testHasUpperAlphaPass() {
        for (String password : studentPasswords) {
            try {
                assertTrue(PasswordCheckerUtility.hasUpperAlpha(password));
            } catch (NoUpperAlphaException e) {
                fail("Unexpected NoUpperAlphaException");
            }
        }
    }

    @Test
    public void testHasUpperAlphaFail() {
        try {
            PasswordCheckerUtility.hasUpperAlpha("lowercasepassword");
            fail("Expected NoUpperAlphaException, but no exception was thrown");
        } catch (NoUpperAlphaException e) {
            assertEquals("Password doesn't have an uppercase character A-Z!", e.getMessage());
        }
    }

    @Test
    public void testHasLowerAlphaPass() {
        for (String password : studentPasswords) {
            try {
                assertTrue(PasswordCheckerUtility.hasLowerAlpha(password));
            } catch (NoLowerAlphaException e) {
                fail("Unexpected NoLowerAlphaException");
            }
        }
    }

    @Test
    public void testHasLowerAlphaFail() {
        try {
            PasswordCheckerUtility.hasLowerAlpha("UPPERCASEPASSWORD");
            fail("Expected NoLowerAlphaException, but no exception was thrown");
        } catch (NoLowerAlphaException e) {
            assertEquals("The password must contain at least one lowercase alphabetic character", e.getMessage());
        }
    }

    @Test
    public void testHasDigitPass() {
        for (String password : studentPasswords) {
            try {
                assertTrue(PasswordCheckerUtility.hasDigit(password));
            } catch (NoDigitException e) {
                fail("Unexpected NoDigitException");
            }
        }
    }

    @Test
    public void testHasDigitFail() {
        try {
            PasswordCheckerUtility.hasDigit("NoDigitsPassword");
            fail("Expected NoDigitException, but no exception was thrown");
        } catch (NoDigitException e) {
            assertEquals("Password must have a numerical digit 0-9.", e.getMessage());
        }
    }

    @Test
    public void testHasSpecialCharPass() {
        for (String password : studentPasswords) {
            try {
                assertTrue(PasswordCheckerUtility.hasSpecialChar(password));
            } catch (NoSpecialCharacterException e) {
                fail("Unexpected NoSpecialCharacterException");
            }
        }
    }

    @Test
    public void testHasSpecialCharFail() {
        try {
            PasswordCheckerUtility.hasSpecialChar("NoSpecialCharacterPassword");
            fail("Expected NoSpecialCharacterException, but no exception was thrown");
        } catch (NoSpecialCharacterException e) {
            assertEquals("The password must contain at least one special character", e.getMessage());
        }
    }

    @Test
    public void testNoSameCharInSequencePass() {
        for (String password : studentPasswords) {
            try {
                assertFalse(PasswordCheckerUtility.NoSameCharInSequence(password));
            } catch (InvalidSequenceException e) {
            }
        }
    }

    @Test
    public void testNoSameCharInSequenceFail() {
        try {
            PasswordCheckerUtility.NoSameCharInSequence("aaBSON78&");
            fail("Expected InvalidSequenceException, but no exception was thrown");
        } catch (InvalidSequenceException e) {
            assertEquals("Password shouldn't have two of the same characters in sequence in a row.", e.getMessage());
        }
    }

    @Test
    public void testIsValidPasswordPass() {
        for (String password : studentPasswords) {
            try {
                assertTrue(PasswordCheckerUtility.isValidPassword(password));
            } catch (LengthException | NoUpperAlphaException | NoLowerAlphaException |
                    NoDigitException | NoSpecialCharacterException | InvalidSequenceException e) {
            }
        }
    }

    @Test
    public void testIsValidPasswordFail() {
        try {
            PasswordCheckerUtility.isValidPassword("Wead");
        } catch (LengthException e) {
            assertEquals("The password must be at least 6 characters long", e.getMessage());
        } catch (NoUpperAlphaException e) {
            assertEquals("Password must contain an uppercase alpha character", e.getMessage());
        } catch (NoLowerAlphaException e) {
            assertEquals("Password must contain a lowercase alpha character", e.getMessage());
        } catch (NoDigitException e) {
            assertEquals("Password must contain a numeric character", e.getMessage());
        } catch (NoSpecialCharacterException e) {
            assertEquals("Password must contain a special character", e.getMessage());
        } catch (InvalidSequenceException e) {
            assertEquals("Password cannot contain more than 2 of the same character in sequence", e.getMessage());
        }
    }

    @Test
    public void testHasBetweenSixAndNineCharsPass() {
 
            assertTrue(PasswordCheckerUtility.hasBetweenSixAndNineChars("123456t"));
        }
    

    @Test
    public void testHasBetweenSixAndNineCharsFail() {
        assertFalse(PasswordCheckerUtility.hasBetweenSixAndNineChars("12345678910"));
    }

    @Test
    public void testIsWeakPasswordPass() {
        for (String password : studentPasswords) {
            try {
                assertFalse(PasswordCheckerUtility.isWeakPassword(password));
            } catch (WeakPasswordException e) {
                fail("Unexpected WeakPasswordException");
            }
        }
    }

    @Test
    public void testIsWeakPasswordFail() {
        try {
            PasswordCheckerUtility.isWeakPassword("ShortP12!");
            fail("Expected WeakPasswordException, but no exception was thrown");
        } catch (WeakPasswordException e) {
            assertEquals("Password is OK, but weak. Contains 9 or less characters.", e.getMessage());
        }
    }

    @Test
    public void testGetInvalidPasswords() {
        ArrayList<String> invalidPasswords = PasswordCheckerUtility.getInvalidPasswords(studentPasswords);
        assertEquals(2, invalidPasswords.size());
    }
}