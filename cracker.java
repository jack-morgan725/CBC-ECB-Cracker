		
import java.io.*; 
import java.nio.charset.Charset;
import java.util.HashMap;

/**
* Cracker class uses a plaintext and ciphertext to obtain a substitution key which is then used to 
* decipher a second ciphertext file that no plaintext is known. Cracker has two modes. CBC and ECB.
*
* @author Jack Morgan
* @version 1.0
* @since 2019-02-12
*
* Command P1.1: java -jar cracker.jar ECB ECB_c1.txt ECB_p1.txt ECB_c2.txt Output.txt
* Command P1.2: java -jar cracker.jar CBC CBC_iv=2_c1.txt CBC_iv=2_p1.txt CBC_iv=22_c2.txt Output.txt 2 22 
*/
public class cracker
{
	/**
	* Accepts a set of string arguments from the terminal, assigns the provided input, and calls the method
	* associated with the mode java selected by the user.
	* @param args[0] cipherMode the cipher mode to be used. Either CBC or ECB.
	* @param args[1] ciphertextOneFilename the name of the initial cipher text file. 
	* @param args[2] plaintextOneFilename the name of the initial plain text file.
	* @param args[3] ciphertextTwoFilename the name of the second cipher text file.
	* @param args[4] outputFilename the name of the file that the program results should be written to. 
	* @param args[5] initializationVectorOne the IV for the initial ciphertext and plaintext.
	* @param args[6] initializationVectorTwo the IV for the second ciphertext.
	*/
	public static void main(String[] args) 
	{
		if (args.length < 4) {
			System.out.println("Not enough arguments entered.");
			return;
		}
		
		String cipherMode = args[0];
		String ciphertextOneFilename = args[1];
		String plaintextOneFilename = args[2];
		String ciphertextTwoFilename = args[3];
		String outputFilename = args[4];
		
		if (cipherMode.equals("CBC") && args.length == 7) 
		{
			String initializationVectorOne = args[5];
			String initializationVectorTwo = args[6];
			cracker.modeCBC(plaintextOneFilename, 
							ciphertextOneFilename, 
							ciphertextTwoFilename, 
							outputFilename, 
							initializationVectorOne, 
							initializationVectorTwo);
		} else if (cipherMode.equals("ECB"))
			cracker.modeEBC(plaintextOneFilename, 
							ciphertextOneFilename, 
							ciphertextTwoFilename, 
							outputFilename);
		else 
			System.out.println("Invalid cipher mode entered.");
	}
	
	/**
	* Finds the substitution key for the second ECB ciphertext file using the initial plaintext and ciphertext files and deciphers it.
	* Results are written to the specified filename.
	* @param plaintextFilename this is the name of the initial plaintext file that is used to obtain the substitution key for the second ciphertext file.
	* @param ciphertextFilenameOne this is the name of the initial ciphertext file that is used to obtain the substitution key for the second ciphertext file.
	* @param outputFilename this is the name of the file that the results of the deciphered file are written to.
	*/
	public static void modeEBC(String plaintextFilename, 
							   String ciphertextFilenameOne, 
							   String ciphertextFilenameTwo, 
							   String outputFilename) 
	{
		HashMap<Character, Character> keyHash = new HashMap<Character, Character>();
		int pChar, cChar;
		
		//--> Get substitution key for P1/C1.
		try 
		{
			//--> Read in C1 cipertext and its corresponding plaintext P1.
			BufferedReader plainReader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(plaintextFilename)), Charset.forName("UTF-8")));
			BufferedReader cipherReader = new BufferedReader(new InputStreamReader(new FileInputStream(new File(ciphertextFilenameOne)), Charset.forName("UTF-8")));
			
			//--> Loop through files one character at a time.
			while ((pChar = (int)plainReader.read()) != -1 && (cChar = (int)cipherReader.read()) != -1) 
			{				
				//--> If that character hasn't been mapped yet (i.e key has default value 0) -> map it.
				if (keyHash.get((char) cChar) == null) 
					keyHash.put((char) cChar, (char) pChar);
			}
			
			cracker.printOutKey(keyHash);
			
			//--> Crack the second ciphertext.
			File cipherTextTwo = new File(ciphertextFilenameTwo);
			cipherReader = new BufferedReader(new InputStreamReader(new FileInputStream(cipherTextTwo), Charset.forName("UTF-8")));
			char[] cipherTextFile = new char[(int)cipherTextTwo.length()];
			char[] decipheredTextFile = new char[(int)cipherTextTwo.length()];
			
			int i = 0;
			while ((cChar = (int)cipherReader.read()) != -1) 
			{
				char cipherCharacter = (char) cChar;
				decipheredTextFile[i] = keyHash.get(cipherCharacter);
				i++;
			}
			
			//--> Write out the results of the cracked ciphertext.
			cracker.writeOutFile(new String(decipheredTextFile), outputFilename);
		}
		catch(IOException e) 
		{
			System.out.println("Invalid parameters supplied.");
		}
	}
	
	/**
	* Finds the substitution key for the second CBC ciphertext file using the initial plaintext and ciphertext files and deciphers it.
	* Results are written to the specified filename.
	* @param plaintextFilename this is the name of the initial plaintext file that is used to obtain the substitution key for the second ciphertext file.
	* @param ciphertextFilenameOne this is the name of the initial ciphertext file that is used to obtain the substitution key for the second ciphertext file.
	* @param outputFilename this is the name of the file that the results of the deciphered file are written to.
	* @param initializationVectorOne this is the IV for the initial ciphertext and plaintext.
	* @param initializationVectorTwo this is the IV for the second ciphertext.
	*/
	public static void modeCBC(String plaintextFilename, 
							   String ciphertextFilenameOne, 
							   String ciphertextFilenameTwo, 
							   String outputFilename, 
							   String initializationVectorOne, 
							   String initializationVectorTwo) 
	{
		HashMap<Character, Character> keyValueHash = new HashMap<Character, Character>();
		int plainTextCharacterPlusIV = 0, actualPlainTextCharacterPlusIV = 0, ivOne = Integer.parseInt(initializationVectorOne), ivTwo = Integer.parseInt(initializationVectorTwo),  pChar, cChar;
		
		File ciphertextOne = new File(ciphertextFilenameOne);
		File plaintextOne  = new File(plaintextFilename);
		char[] cipherTextFile = new char[(int)ciphertextOne.length()];
		
		try 
		{
			BufferedReader plainReaderThree = new BufferedReader(new InputStreamReader(new FileInputStream(plaintextOne), Charset.forName("UTF-8")));
			BufferedReader cipherReaderThree = new BufferedReader(new InputStreamReader(new FileInputStream(ciphertextOne), Charset.forName("UTF-8")));
			
			while ((pChar = (int)plainReaderThree.read()) != -1 && (cChar = (int)cipherReaderThree.read()) != -1) 
			{			
				//--> Calcualte the MX + IV state of the plaintext character.
				plainTextCharacterPlusIV = (ivOne + (pChar-97)) % 26; 	
				actualPlainTextCharacterPlusIV = (plainTextCharacterPlusIV + 97);
				
				//--> Check if mapping for the current cipher character already exists.
				if (keyValueHash.get(actualPlainTextCharacterPlusIV) == null) 
					keyValueHash.put((char)cChar, (char)actualPlainTextCharacterPlusIV);
				
				ivOne = (cChar-97);
			}
		}
		catch(IOException e) 
		{ 
			e.printStackTrace(); 
		}		
		
		cracker.printOutKey(keyValueHash);
		DecryptCBC(ciphertextFilenameTwo, keyValueHash, ivTwo, outputFilename);
	}

	/**
	* Decrypts a ciphertext file that is encrypted using a substitution CBC block cipher.
	* @param filename this is the name of the ciphertext file that should be decrypted.
	* @param key this is the substitution key for the ciphertext file.
	* @param initializationVectorTwo this is the IV for the ciphertext file.
	* @param outputFilename this is the IV for the ciphertext that should be decrypted. 
	*/
	public static void DecryptCBC(String filename, HashMap<Character, Character> key, int initializationVectorTwo, String outputFilename) 
	{	
		try 
		{	
			//--> Read in the file that needs to be deciphered.
			File ciphertext = new File(filename);
			FileInputStream fis = new FileInputStream(ciphertext);
			byte[] data = new byte[(int) ciphertext.length()];
			fis.read(data);
			fis.close();
			
			int iv = 0, ivModPlainTextCharacter = 0;
			char[] cipherTextCharacters = new String(data, "UTF-8").toCharArray();
			char[] decryptedFile = new char[(int)ciphertext.length()];
		
			//--> Start at the end of the file and work backwards.
			for (int i = cipherTextCharacters.length-1; i >= 0; i--) 
			{
				//--> Run ciphertext character through key to get the (IV + MX) state of the plaintext character.
				ivModPlainTextCharacter = key.get(cipherTextCharacters[i]);
				
				//--> IV = Previous character in the cipher text for all blocks excluding the intial block.
				if (i > 0)
					iv = (cipherTextCharacters[i-1])-97;
				else 
					iv = initializationVectorTwo;
				
				//--> Reversing the modulus operation that was initially applied to the plaintext character.
				int plainTextCharacter = ((ivModPlainTextCharacter-97) - iv) % 26; 
				
				if (plainTextCharacter < 0)
					plainTextCharacter += 26;
				
				//--> Store the plain text character and repeat for all other characters.
				decryptedFile[i] = (char)(plainTextCharacter + 97);
			}
			
			//--> Write out the results of the decryption to the specified filename.
			cracker.writeOutFile(new String(decryptedFile), outputFilename);
		}
		catch(IOException e) 
		{ 
			System.out.println("Invalid parameters supplied.");
		}
	}
	
	/**
	* Writes a String to disc at using the provided filename.
	* @param decipheredTextFile this is the contents that will be written to the disc.
	* @param filename this is the name of the file where the contents will be stored.
	*/
	public static void writeOutFile(String decipheredTextFile, String filename) 
	{
		try 
		{
			BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
			writer.write(decipheredTextFile);
			writer.close();
		}
		catch(IOException e) 
		{
			System.out.println("Invalid parameters supplied.");
		}
	}
	
	/**
	* Prints out a provided substitution key to the terminal.
	* @param keyValueHash contains the mappings between a set of ciphertext and plaintext characters.
	*/
	public static void printOutKey(HashMap<Character, Character> keyValueHash) 
	{
		for (Character characterName: keyValueHash.keySet())
		{
            Character key = characterName;
			Character value = keyValueHash.get(characterName);  
			System.out.printf("%c => %c%n", value, key);	
		}
	}
}
