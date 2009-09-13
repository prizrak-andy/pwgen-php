<?php
	/**
	 * Port of the famous GNU/Linux Password Generator ("pwgen") to PHP.
	 * This file may be distributed under the terms of the GNU Public License.
	 * Copyright (C) 2001, 2002 by Theodore Ts'o <tytso@alum.mit.edu>
	 * Copyright (C) 2009 by Superwayne <superwayne@superwayne.org>
	 */
	class PWGen {
		// Flags for the pwgen function
		const PW_DIGITS = 0x0001;
		const PW_UPPERS = 0x0002; // At least one upper letter
		const PW_SYMBOLS = 0x0004;
		const PW_AMBIGUOUS = 0x0008;
		const PW_NO_VOWELS = 0x0010;

		// Flags for the pwgen element
		const CONSONANT = 0x0001; 	// Konsonant, Mitlaut (b, c, ...)
		const VOWEL = 0x0002;		// Vokal, Selbstlaut (a, e, i, o, u)
		const DIPHTHONG = 0x0004;	// Zwielaut (ei, au, ...)
		const NOT_FIRST = 0x0008;

		private $pw_length;
		private $pwgen_flags;
		private $pwgen;
		private $password;

		private static $filled = false;
		private static $elements;
		private static $pw_ambiguous;
		private static $pw_symbols;
		private static $pw_digits;
		private static $pw_uppers;
		private static $pw_lowers;

		/**
		 * @param length	Length of the generated password.
		 * @param no_numerals	Don't include numbers in the generated passwords.
		 * @param no_capitalize	Don't bother to include any capital letters in the generated passwords.
		 * @param ambiguous	Don't use characters that could be confused by the user when printed,
		 * 			such as 'l' and '1', or '0' or 'O'. This reduces the number of possible
		 *			passwords significantly, and as such reduces the quality of the passwords.
		 *			It may be useful for users who have bad vision, but in general use of this
		 *			option is not recommended.
		 * @param capitalize	Include at least one capital letter in the password. This is the default.
		 * @param numerals	Include at least one number in the password. This is the default.
		 * @param secure	Generate completely random, hard-to-memorize passwords. These should only
		 * 			be used for machine passwords, since otherwise it's almost guaranteed that
		 * 			users will simply write the password on a piece of paper taped to the monitor...
		 * @param no-vowels	Generate random passwords that do not contain vowels or numbers that might be
		 * 			mistaken for vowels. It provides less secure passwords to allow system
		 * 			administrators to not have to worry with random passwords accidentally contain
		 * 			offensive substrings.
		 * @param symbols	Include at least one special character in the password.
		 */
		function __construct($length=8, $no_numerals=false, $no_capitalize=false, $ambiguous=false,
			$capitalize=true, $numerals=true, $secure=false, $no_vovels=false, $symbols=false) {
			self::fill_static();

			$this->pwgen = 'pw_phonemes';

			if (is_numeric($length) && $length > 0) {
				$this->pw_length = $length;
				if ($this->pw_length < 5) {
					$pwgen = &$this->pw_rand;
				}
				if ($this->pw_length <= 2) {
					$this->pwgen_flags &= ~self::PW_UPPERS;
				}
				if ($this->pw_length <= 1) {
					$this->pwgen_flags &= ~self::PW_DIGITS;
				}
			} else {
				$this->pw_length = 8;
			}
			if($no_numerals) {
				$this->pwgen_flags &= ~self::PW_DIGITS;
			}
			if($no_capitalize) {
				$this->pwgen_flags &= ~self::PW_UPPERS;
			}
			if($ambiguous) {
				$this->pwgen_flags |= self::AMBIGUOUS;
			}
			if($capitalize) {
				$this->pwgen_flags |= self::PW_DIGITS;
			}
			if($numerals) {
				$this->pwgen_flags |= self::PW_DIGITS;
			}
			if($secure) {
				$this->pwgen = 'pw_rand';
				$this->pwgen_flags |= self::PW_DIGITS | self::PW_UPPERS;
			}
			if($symbols) {
				$this->pwgen_flags |= self::PW_SYMBOLS;
			}
			if($no_vovels) {
				$this->pwgen = 'pw_rand';
				$this->pwgen_flags |= self::NO_VOWELS | self::PW_DIGITS | self::PW_UPPERS;
			}
		}

		function calculate() {
			if($this->pwgen == 'pw_phonemes') 
				$this->pw_phonemes();
			else if($this->pwgen == 'pw_rand')
				$this->pw_rand();
			return $this->password;
		}

		private function pw_phonemes() {
			$this->password = array();
	
			do {
				$feature_flags = $this->pwgen_flags;
				$c = 0;
				$prev = 0;
				$should_be = mt_rand(0, 1) ? self::VOWEL : self::CONSONANT;
				$first = 1;

				while ($c < $this->pw_length) {
					$i = mt_rand(0, count(self::$elements)-1);
					$str = self::$elements[$i]->str;
					$len = strlen($str);
					$flags = self::$elements[$i]->flags;
	
					// Filter on the basic type of the next element
					if (($flags & $should_be) == 0)
						continue;
					// Handle the NOT_FIRST flag
					if ($first && ($flags & self::NOT_FIRST))
						continue;
					// Don't allow VOWEL followed a Vowel/Dipthong pair
					if (($prev & self::VOWEL) && ($flags & self::VOWEL) && ($flags & self::DIPHTHONG))
						continue;
					// Don't allow us to overflow the buffer
					if ($len > $this->pw_length-$c)
						continue;
	
					/* Handle the AMBIGUOUS flag */
					if ($this->pwgen_flags & self::PW_AMBIGUOUS) {
						if (strpbrk($str, self::$pw_ambiguous) !== false)
							continue;
					}
	
					/*
					 * OK, we found an element which matches our criteria,
					 * let's do it!
					 */
					for($j=$c; $j < $len; $j++)
						$this->password[$c+$j] = $str[$j];
	
					/* Handle PW_UPPERS */
					if ($this->pwgen_flags & self::PW_UPPERS) {
						if (($first || $flags & self::CONSONANT) && (mt_rand(0, 9) < 2)) {
							$this->password[$c] = strtoupper($this->password[$c]);
							$feature_flags &= ~self::PW_UPPERS;
						}
					}
			
					$c += $len;
			
					/* Time to stop? */
					if ($c >= $this->pw_length)
						return;
			
					/*
					 * Handle PW_DIGITS
					 */
					if ($this->pwgen_flags & self::PW_DIGITS) {
						if (!$first && (mt_rand(0, 9) < 3)) {
							do {
								$ch = strval(mt_rand(0, 9));
							} while (($this->pwgen_flags & self::PW_AMBIGUOUS) && strchr(self::$pw_ambiguous, $ch));
							$this->password[$c++] = $ch; //FIXME
							$this->password[$c] = 0;
							$feature_flags &= ~self::PW_DIGITS;
					
							$first = 1;
							$prev = 0;
							$should_be = mt_rand(0, 1) ? self::VOWEL : self::CONSONANT;
							continue;
						}
					}
					
					/* Handle PW_SYMBOLS */
					if ($this->pwgen_flags & self::PW_SYMBOLS) {
						if (!$first && (mt_rand(0, 9) < 2)) {
							do {
								$ch = self::$pw_symbols[mt_rand(0, strlen(self::$pw_symbols)-1)];
							} while (($this->pwgen_flags & self::PW_AMBIGUOUS) && strchr(self::$pw_ambiguous, $ch));
							$this->password[$c++] = $ch; //FIXME
							$this->password[$c] = 0;
							$feature_flags &= ~self::PW_SYMBOLS;
						}
					}
	
					/*
					 * OK, figure out what the next element should be
					 */
					if ($should_be == self::CONSONANT) {
						$should_be = self::VOWEL;
					} else { /* should_be == VOWEL */
						if (($prev & self::VOWEL) || ($flags & self::DIPHTHONG) || (mt_rand(0, 9) > 3))
							$should_be = self::CONSONANT;
						else
							$should_be = self::VOWEL;
					}
					$prev = $flags;
					$first = 0;
				}
			} while ($feature_flags & (self::PW_UPPERS | self::PW_DIGITS | self::PW_SYMBOLS));
		}

		function pw_rand() {
			echo 'pw_rand called ...';
		}

		static function fill_static() {
			if(self::$filled === false) {
				self::$elements = array(
					new PWElement('a', self::VOWEL),
					new PWElement('ae', self::VOWEL | self::DIPHTHONG),
					new PWElement('ah', self::VOWEL | self::DIPHTHONG),
					new PWElement('ai', self::VOWEL | self::DIPHTHONG),
					new PWElement('b', self::CONSONANT),
					new PWElement('c', self::CONSONANT),
					new PWElement('ch', self::CONSONANT | self::DIPHTHONG),
					new PWElement('d', self::CONSONANT),
					new PWElement('e', self::VOWEL),
					new PWElement('ee', self::VOWEL | self::DIPHTHONG),
					new PWElement('ei', self::VOWEL | self::DIPHTHONG),
					new PWElement('f', self::CONSONANT),
					new PWElement('g', self::CONSONANT),
					new PWElement('gh', self::CONSONANT | self::DIPHTHONG | self::NOT_FIRST),
					new PWElement('h', self::CONSONANT),
					new PWElement('i', self::VOWEL),
					new PWElement('ie', self::VOWEL | self::DIPHTHONG),
					new PWElement('j', self::CONSONANT),
					new PWElement('k', self::CONSONANT),
					new PWElement('l', self::CONSONANT),
					new PWElement('m', self::CONSONANT),
					new PWElement('n', self::CONSONANT),
					new PWElement('ng', self::CONSONANT | self::DIPHTHONG | self::NOT_FIRST),
					new PWElement('o', self::VOWEL),
					new PWElement('oh', self::VOWEL | self::DIPHTHONG),
					new PWElement('oo', self::VOWEL | self::DIPHTHONG),
					new PWElement('p', self::CONSONANT),
					new PWElement('ph', self::CONSONANT | self::DIPHTHONG),
					new PWElement('qu', self::CONSONANT | self::DIPHTHONG),
					new PWElement('r', self::CONSONANT),
					new PWElement('s', self::CONSONANT),
					new PWElement('sh', self::CONSONANT | self::DIPHTHONG),
					new PWElement('t', self::CONSONANT),
					new PWElement('th', self::CONSONANT | self::DIPHTHONG),
					new PWElement('u', self::VOWEL),
					new PWElement('v', self::CONSONANT),
					new PWElement('w', self::CONSONANT),
					new PWElement('x', self::CONSONANT),
					new PWElement('y', self::CONSONANT),
					new PWElement('z', self::CONSONANT)
				);
				self::$pw_ambiguous = 'B8G6I1l0OQDS5Z2';
				self::$pw_symbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
				self::$pw_digits = '0123456789';
				self::$pw_uppers = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
				self::$pw_lowers = 'abcdefghijklmnopqrstuvwxyz';
			}
		}

	}

	class PWElement {
		public $str;
		public $flags;	
		
		public function __construct($str, $flags) {
			$this->str = $str;
			$this->flags = $flags;
		}
	}
?>
