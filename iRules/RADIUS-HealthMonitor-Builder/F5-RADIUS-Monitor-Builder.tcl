when HTTP_REQUEST {
	
	############################################################################
	#+ Handler for Login Page HTTP response
	#
	
	#log "Checking if HTTP POST request has been send."

	if { ( [HTTP::method] eq "POST" )
	 and ( [HTTP::header value "Content-Length"] >= 0 ) } then {

		############################################################################
		#+ Handler to collect HTTP POST data
		#

		#log "A POST request has been received. Collecting the HTTP POST request payload based on provided Content-Length value."

		HTTP::collect [HTTP::header value "Content-Length"]

		#
		# Handler to collect HTTP POST data
		############################################################################	
	
	} else {
		
		############################################################################
		#+ Handler to define Login Form HTML
		#

		#log "A GET request has been received. Constructing the HTML response page."

		set html(login_form) \
{
<!DOCTYPE html> 
<html> 
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<title> Monitor Builder </title>
<style> 
Body { font-family: Calibri, Helvetica, sans-serif; background-color: white; }
.centerbox { margin: auto; width: 500px; }
.container { padding: 25px; background-color: lightgray;}
button { background-color: gray; width: 100%; color: white; padding: 15px; margin: 10px 0px; border: none; cursor: pointer; } 
form { border: 3px solid #f1f1f1; } 
input[type=text], input[type=password], select { width: 100%; margin: 8px 0; padding: 12px 20px; display: inline-block; border: 2px solid gray; box-sizing: border-box; }
button:hover { opacity: 0.7; }
</style> 
</head>  
<body>
	<div class="centerbox">
		<center> <h1> F5 RADIUS Monitor Builder </h1> </center> 
		<form action="/" method="post">
			<div class="container">
				<label>TMSH Monitor Name : </label> 
				<input type="text" placeholder="Enter Monitor Name" name="monitor_name" required>
				<label>RADIUS Shared-Key : </label> 
				<input type="text" placeholder="Enter Shared-Key" name="shared_key" required>
				<label>TMSH NAS-ID Attribute Value : </label> 
				<input type="text" placeholder="Enter Attribute Value" name="nas_id_value" required>
				<label for="hmac_mode">HMAC-based Authenticator Mode:</label>
				<select id="hmac_mode" name="hmac_mode">
					<option value="0">Disable</option>
					<option value="1" selected>Compute HMAC-based Authenticator</option>
				</select>
				<label>RADIUS Username : </label> 
				<input type="text" placeholder="Enter Username" name="username" required>
				<label>RADIUS Password : </label> 
				<input type="text" placeholder="Empty Value" name="password">
				<label for="response_code">Expected RADIUS Response Code :</label>
				<select id="response_code" name="response_code">
					<option value="2">ACCEPT</option>
					<option value="3">REJECT</option>
					<option value="11">CHALLENGE</option>  
				</select>
				<button type="submit">Generate</button> 
			</div>
		</form>
	</div>
</body>   
</html>
}

		#
		# Handler to define Login Form HTML
		############################################################################

		############################################################################
		#+ Handler to respond HTML Login Form
		#

		#log "Sending HTTP response to the client."

		HTTP::respond 200 content $html(login_form) "Content-Type" "text/html"

		#
		# Handler to respond HTML Login Form
		############################################################################

	}

	#
	# Handler for Login Page HTTP response
	############################################################################
	
}

when HTTP_REQUEST_DATA {
	
	############################################################################
	#+ Handler to extract HTTP POST Data
	#

	#log "Constructing URI query string from received HTTP payload."
	
	set temp(post_data) "?[HTTP::payload]"
	
	#log "Extracting FORMs data from the URI query string."
	
	set temp(post_monitor_name) 	[URI::decode [URI::query $temp(post_data) "monitor_name"]]
	set temp(post_shared_key) 		[URI::decode [URI::query $temp(post_data) "shared_key"]]
	set temp(post_nas_id_value) 	[URI::decode [URI::query $temp(post_data) "nas_id_value"]]
	set temp(post_hmac_mode) 		[URI::decode [URI::query $temp(post_data) "hmac_mode"]]
	set temp(post_username) 		[URI::decode [URI::query $temp(post_data) "username"]]
	set temp(post_password) 		[URI::decode [URI::query $temp(post_data) "password"]]
	set temp(post_response_code) 	[URI::decode [URI::query $temp(post_data) "response_code"]]

	#log "Checking if the provided information is sufficient to process the request."

	if { ( $temp(post_monitor_name) ne "" )
	 and ( $temp(post_shared_key) ne "" )
	 and ( ( $temp(post_hmac_mode) == 0 )
	    or ( $temp(post_hmac_mode) == 1 ) )
	 and ( $temp(post_username) ne "" )
	 and ( ( $temp(post_response_code) == 2 ) 
        or ( $temp(post_response_code) == 3 ) 
        or ( $temp(post_response_code) == 11 ) ) } then {
		
		#log "The provided information is sufficient to process the request."

	} else {
		
		############################################################################
		#+ Handler to redirect back to Login Form
		#

		#log "The provided information is not sufficient to process the request. Sending HTTP redirect to the client."

		HTTP::respond 302 "location" "/"
		
		#
		# Handler to redirect back to Login Form
		############################################################################
		
	}
	
	#
	# Handler to extract HTTP POST Data
	############################################################################

	#######################################################################
	#+ Handler for RADIUS request construction
	#

	#######################################################################
	#+ Handler for RADIUS request ID and request authenticator generation
	#

	#log "Setting the RADIUS request ID always to \"1\" (aka. we use a singleplex connection handling)."

	set temp(request_id) 1

	#log "Calculating a random RADIUS request authenticator based on a MD5 of \"RADIUS ShareKey+TMM Core+Epoch Time\"."

	set temp(request_authenticator) [md5 "$temp(post_shared_key)[TMM::cmp_unit][clock clicks]"]

	#
	# Handler for RADIUS request ID and request authenticator generation
	#######################################################################

	#######################################################################
	#+ Handler for RADIUS request attribute construction
	#
	# 0               1               2               3               4 byte
	# 0                   1                   2                   3
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Attr1-Code   |  Attr1-Length |         Attr1-Value           |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Attr1-Value (cont) ...       |  AttrN-Code   |  AttrN-Length |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  					   AttrN-Value (cont) ...                 |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  AttrN-Value (cont) ...

	#log "Starting to contruct the RADIUS request attributes."

	#######################################################################
	#+ Handler for RADIUS request username attribute generation
	#

	#log "Contructing the RADIUS USERNAME attribute."

	append temp(request_attributes_field) [binary format cca*\
															1\
															[expr { 2 + [string length $temp(post_username)] }]\
															$temp(post_username)\
											]

	append temp(request_attributes_field) [binary format cca*\
															32\
															[expr { 2 + [string length $temp(post_nas_id_value)] }]\
															$temp(post_nas_id_value)\
											]
											
	#
	# Handler for RADIUS request username attribute generation
	#######################################################################

	#######################################################################
	#+ Handler for RADIUS request password attribute encryption and generation
	#

	#log "Checking if a Password value was provided."

	if { $temp(post_password) ne "" } then {
			
		#log "Password value set. Constructing RADIUS PASSWORD request attribute."

		#######################################################################
		#+ Handler for RADIUS password attribute encryption
		#

		#log "Encrypting the provided RADIUS request password value."
		#log "Checking if the provided password value completely fills one or many 16-byte / 128-bit cipher block(s)."

		if { [string length $temp(post_password)] % 16 > 0 } then {

			#log "The password value does not fill one or many 16-byte / 128-bit cipher block(s)."
			#log "Zero-Padding the password value to a multiple of 16-byte / 128-bit to completely fill one or many 16-byte / 128-bit cipher block(s)."

			set temp(padded_password) [binary format a[expr { ( int( [string length $temp(post_password)] / 16 ) + 1 ) * 16 }] $temp(post_password)]

		} else {

			#log "The password value does fill one or many 16-byte / 128-bit cipher block(s)."
		
			set temp(padded_password) $temp(post_password)
		
		}

		#log "Checking if the provided password value is stored in one or many 16-byte / 128-bit cipher block(s)."

		if { [string length $temp(padded_password)] == 16 } then {

			#log "The password can be stored in a single 16-byte / 128-bit cipher block. Using an optimized function to encrypt the contained password value."
			#log "Chunking and converting the plaintext password value into two subsequent 64-bit integer values."

			binary scan $temp(padded_password) WW\
											temp(plaintext_password_64bit_chunk_1)\
											temp(plaintext_password_64bit_chunk_2)

			#log "Calculating the 128-bit encryption key using the RADIUS-Shared-Secret and the randomly generated RADIUS request authenticator value."
			#log "Chunking and converting the generated 128-bit encryption key into two 64-bit integer values."

			binary scan [md5 "$temp(post_shared_key)$temp(request_authenticator)"] WW\
																			temp(encryption_key_64bit_chunk_1)\
																			temp(encryption_key_64bit_chunk_2)

			#log "Performing XOR operation with the corresponding plaintext block / encryption key 64-bit integer values."
			#log "Converting the encrypted 64-bit integer password values to their binary representation."

			set temp(encrypted_password) [binary format WW\
															[expr { $temp(plaintext_password_64bit_chunk_1) ^ $temp(encryption_key_64bit_chunk_1) }]\
															[expr { $temp(plaintext_password_64bit_chunk_2) ^ $temp(encryption_key_64bit_chunk_2) }]\
											]

		} else {

			#log "The password must be stored in more than one 16-byte / 128-bit cipher block(s). Using the generic function to encrypt the contained password value."
			#log "Chunking and converting the password value into a list of subsequent 64-bit integer values."

			binary scan $temp(padded_password) W* temp(plaintext_password_64bit_chunks)

			#log "Set the initial key seed to the randomly generated RADIUS request authenticator value."

			set temp(encryption_iv) $temp(request_authenticator)

			#log "Looping pair-wise through the list of password chunks to encrypt a full cipher block at once and then rotate the key for the next block."

			foreach { temp(plaintext_password_64bit_chunk_1) temp(plaintext_password_64bit_chunk_2) } $temp(plaintext_password_64bit_chunks) {

				#log "Calculating the 128-bit encryption key using the RADIUS-Shared-Secret and current key seed as input."
				#log "Chunking and converting the generated 128-bit encryption key into two 64-bit integer values."

				binary scan [md5 "$temp(post_shared_key)$temp(encryption_iv)"] WW\
																		temp(encryption_key_64bit_chunk_1)\
																		temp(encryption_key_64bit_chunk_2)

				#log "Performing XOR operation with the corresponding cipher block / encryption key 64-bit integers."
				#log "Appending the encrypted 64-bit integers password values to the list of already encrypted values."

				lappend temp(encrypted_password_64bit_chunks) [expr { $temp(plaintext_password_64bit_chunk_1) ^ $temp(encryption_key_64bit_chunk_1) }]\
																[expr { $temp(plaintext_password_64bit_chunk_2) ^ $temp(encryption_key_64bit_chunk_2) }]

				#log "Setting the encryption key seed for the next cipher block to the encrypted value of the current cipher block."

				set temp(encryption_iv) [binary format W* [lrange $temp(encrypted_password_64bit_chunks) end-1 end]]

			}

			#log "Converting the list of encrypted 64-bit integer password values to their binary representation."

			set temp(encrypted_password) [binary format W* $temp(encrypted_password_64bit_chunks)]

		}

		#log "Successfully decrypted the provided RADIUS request password value."

		#
		# Handler for RADIUS password attribute encryption
		#######################################################################

		#######################################################################
		#+ Handler for RADIUS request password attribute generation
		#
	
		append temp(request_attributes_field) [binary format cca*\
																	2\
																	[expr { 2 + [string length $temp(encrypted_password)] }]\
																	$temp(encrypted_password)\
													]

		#
		#+ Handler for RADIUS request password attribute generation
		#######################################################################

	} else {
		
		#log "Empty Password value. Skipping construction of RADIUS PASSWORD request attribute."
		
	}

	#
	# Handler for RADIUS request password attribute encryption and generation
	#######################################################################

	#log "Finished to contruct the RADIUS request attributes."

	#
	# Handler for RADIUS request attribute construction
	#######################################################################

	#######################################################################
	#+ Handler for RADIUS request contruction
	#
	# 0               1               2               3               4 byte
	# 0                   1                   2                   3
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 bits
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
	# |      Code     |  Identifier   |            Length             |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |                                                               |
	# |                         Authenticator                         |
	# |                           (16 bytes)                          |
	# |                                                               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  				Default-Attributes  (X bytes)                 |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |    Code 80    |   Length 18  |      HMAC-MD5 Checksum...      |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  ... HMAC-MD5 Checksum ... (16 bytes)

	#log "Check if a HMAC-based RADIUS request authenticator attribute should be included."

	if { $temp(post_hmac_mode) == 1 } then {
	
		#log "A HMAC-based RADIUS request authenticator attribute must be included."
		#log "Calculating the length of the RADIUS request payload by combining the length of request headers (20-bytes), request attributes (n-bytes) and the RADIUS Message Authenticator attribute (18-bytes)."

		set temp(request_length) [expr { 20 + [string length $temp(request_attributes_field)] + 18 }]

		#log "Contructing the RADIUS Access-Request payload by including the RADIUS request code, -identifier, -length, -authenticator, -attributes fields and a HMAC-MD5 based message authenticator."

		set temp(request_payload) [binary format ccSa*a*cca*\
														1\
														$temp(request_id)\
														$temp(request_length)\
														$temp(request_authenticator)\
														$temp(request_attributes_field)\
														80\
														18\
														[CRYPTO::sign -alg hmac-md5 -key $temp(post_shared_key)\
															[binary format ccSa*a*cca*\
																				1\
																				$temp(request_id)\
																				$temp(request_length)\
																				$temp(request_authenticator)\
																				$temp(request_attributes_field)\
																				80\
																				18\
																				"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"\
															]\
														]\
										]
	
	} else {

		#log "A HMAC-based RADIUS request authenticator attribute must not be included."
		#log "Calculating the length of the RADIUS request payload by combining the length of request headers (20-bytes) and request attributes (n-bytes)."

		set temp(request_length) [expr { 20 + [string length $temp(request_attributes_field)] }]

		#log "Contructing the RADIUS Access-Request payload by including the RADIUS request code, -identifier, -length, -authenticator and -attributes fields."

		set temp(request_payload) [binary format ccSa*a*\
														1\
														$temp(request_id)\
														$temp(request_length)\
														$temp(request_authenticator)\
														$temp(request_attributes_field)
									]
	
	}

	#log "Finished construction of the RADIUS Access-Request payload."

	#
	# Handler for RADIUS request contruction
	#######################################################################

	############################################################################
	#+ Handler to Hex Decode the RADIUS request payload
	#
	
	#log "HEX decoding the constructed RADIUS request payload."
	
	binary scan $temp(request_payload) H* temp(request_payload_hex)

	#log "Escaping the HEX encoded RADIUS request payload."
	
	set temp(request_payload_hex_encoded) ""
	foreach { temp(hex_1) temp(hex_2) } [split $temp(request_payload_hex) ""] {
		
		#log "Reading the next two HEX value from the buffer, applying escape sequence and storing it to the output."
		append temp(request_payload_hex_encoded) "\\x$temp(hex_1)$temp(hex_2)"

	}

	#
	#+ Handler to Hex Decode the RADIUS request payload
	############################################################################
	
	############################################################################
	#+ Handler to relay HMAC Mode State
	#

	switch -exact -- $temp(post_hmac_mode) {
		"0" {
			set temp(select_hmac_0) "selected"
			set temp(select_hmac_1) ""
		}
		default {
			set temp(select_hmac_0) ""
			set temp(select_hmac_1) "selected"
		}
	}

	#
	# Handler to relay HMAC Mode State
	############################################################################

	############################################################################
	#+ Handler to relay Response Code State
	#

	switch -exact -- $temp(post_response_code) {
		"3" {
			set temp(select_code_2) ""
			set temp(select_code_3) "selected"
			set temp(select_code_11) ""
			set temp(response_payload_hex_encoded) {\x03\01}
		}
		"11" {
			set temp(select_code_2) ""
			set temp(select_code_3) ""
			set temp(select_code_11) "selected"
			set temp(response_payload_hex_encoded) {\x0b\01}
		}
		default {
			set temp(select_code_2) "selected"
			set temp(select_code_3) ""
			set temp(select_code_11) ""
			set temp(response_payload_hex_encoded) {\x02\01}
		}
	}

	#
	# Handler to relay Radio Button State
	############################################################################

	############################################################################
	#+ Handler to define Result Page HTML
	#
		
		set html(result_page) \
"<!DOCTYPE html> 
<html> 
<head>
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
<title> Monitor Builder </title>
<style> 
Body \{ font-family: Calibri, Helvetica, sans-serif; background-color: white; \}
.centerbox \{ margin: auto; width: 500px; \}
.container \{ padding: 25px; background-color: lightgray;\}
button \{ background-color: gray; width: 100%; color: white; padding: 15px; margin: 10px 0px; border: none; cursor: pointer; \} 
form \{ border: 3px solid #f1f1f1; \} 
input\[type=text\], input\[type=password\], select \{ width: 100%; margin: 8px 0; padding: 12px 20px; display: inline-block; border: 2px solid gray; box-sizing: border-box; \}
button:hover \{ opacity: 0.7; \}
</style> 
</head>  
<body>
	<div class=\"centerbox\">
		<center> <h1> F5 RADIUS Monitor Builder </h1> </center> 
		<form action=\"/\" method=\"post\">
			<div class=\"container\"> 
				<label>TMSH Monitor Name : </label> 
				<input type=\"text\" placeholder=\"Enter Monitor\" name=\"monitor_name\" value=\"$temp(post_monitor_name)\" required>
				<label>RADIUS Shared-Key : </label> 
				<input type=\"text\" placeholder=\"Enter Shared-Key\" name=\"shared_key\" value=\"$temp(post_shared_key)\" required>
				<label>TMSH NAS-ID Attribute Value : </label> 
				<input type=\"text\" placeholder=\"Enter Attribute Value\" name=\"nas_id_value\" value=\"$temp(post_nas_id_value)\" required>
				<label for=\"hmac_mode\">HMAC-based Authenticator Mode:</label>
				<select id=\"hmac_mode\" name=\"hmac_mode\">
					<option value=\"0\" $temp(select_hmac_0)>Disable</option>
					<option value=\"1\" $temp(select_hmac_1)>Compute HMAC-based Authenticator</option>
				</select>
				<label>RADIUS Username : </label> 
				<input type=\"text\" placeholder=\"Enter Username\" name=\"username\" value=\"$temp(post_username)\" required>
				<label>RADIUS Password : </label> 
				<input type=\"text\" placeholder=\"Empty Value\" name=\"password\" value=\"$temp(post_password)\">
				<label for=\"response_code\">Expected RADIUS Response Code :</label>
				<select id=\"response_code\" name=\"response_code\">
					<option value=\"2\" $temp(select_code_2)>ACCEPT</option>
					<option value=\"3\" $temp(select_code_3)>REJECT</option>
					<option value=\"11\" $temp(select_code_11)>CHALLENGE</option>  
				</select>
				<button type=\"submit\">Generate</button> 
			</div>
		</form>
	</div>
	<div class=\"centerbox\">
		<center> <h1> TMSH Monitor Configuration </h1> </center> 
		<div class=\"container\">
			<pre style=\"overflow-y: auto;\">
ltm monitor udp $temp(post_monitor_name) \{
	adaptive disabled
	debug no
	defaults-from udp
	interval 5
	recv $temp(response_payload_hex_encoded) 
	recv-disable none
	send $temp(request_payload_hex_encoded)
	time-until-up 0
	timeout 16
\}
			</pre>
		</div>
	</div>
</body>
</html>"
	
	#
	# Handler to define Result Page HTML
	############################################################################	
	
	############################################################################
	#+ Handler to display HTML Result Page
	#
	
	HTTP::respond 200 content [subst -nobackslashes -nocommands $html(result_page)] "Content-Type" "text/html"
	
	#
	# Handler to display HTML Result Page
	############################################################################

}