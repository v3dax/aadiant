<?php
// secure-mail.php
// Usage: POST form fields. DON'T trust user-supplied admin_email as the "From" or as an arbitrary recipient.

declare(strict_types=1);

// Configuration - set on server, not from user input
const ADMIN_RECIPIENT = 'you@yourdomain.com';     // who receives the email
const MAIL_FROM_NAME  = 'YourSite Contact';
const MAIL_FROM_EMAIL = 'no-reply@yourdomain.com'; // must be a domain you control

// Basic helpers
function sanitize_text(string $s): string {
    // trim, remove null bytes, convert special chars for HTML emails
    $s = trim($s);
    $s = str_replace("\0", '', $s);
    return htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function safe_header_value(string $v): string {
    // remove CR/LF to prevent header injection
    return str_replace(["\r", "\n"], '', $v);
}

function is_valid_email(string $email): bool {
    return (bool) filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Accept only POST for sending (safer)
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Only POST allowed.']);
    exit;
}

// Optional: check CSRF token here if your form implements one
// if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) { ... }

// Grab expected fields safely
$form_subject   = sanitize_text($_POST['form_subject'] ?? 'New contact form submission');
$sender_email   = trim($_POST['email'] ?? '');           // assume form may include 'email'
$sender_name    = sanitize_text($_POST['name'] ?? '');   // optional

// Validate sender email if present (but we won't use as From header)
if ($sender_email !== '' && !is_valid_email($sender_email)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid email address.']);
    exit;
}

// Build message table from POST, excluding internal keys
$exclude_keys = ['project_name', 'admin_email', 'form_subject', 'csrf'];
$message_rows = '';

$alt = false;
foreach ($_POST as $key => $value) {
    if (in_array($key, $exclude_keys, true)) continue;
    $value = (string)$value;
    if ($value === '') continue;

    $alt = !$alt;
    $row_style = $alt ? '' : ' style="background-color:#f8f8f8;"';
    $k = sanitize_text($key);
    $v = sanitize_text($value);
    $message_rows .= "<tr{$row_style}>
        <td style='padding:10px;border:1px solid #e9e9e9;'><strong>{$k}</strong></td>
        <td style='padding:10px;border:1px solid #e9e9e9;'>{$v}</td>
    </tr>\n";
}

if ($message_rows === '') {
    echo json_encode(['status' => 'error', 'message' => 'Form is empty.']);
    exit;
}

$message_html = "<html><body>
    <table style='width:100%;border-collapse:collapse;'>{$message_rows}</table>
    <p>Sent from: " . ($sender_name ?: 'Anonymous') . ($sender_email ? " &lt;".sanitize_text($sender_email)."&gt;" : '') . "</p>
</body></html>";

// Prepare safe headers
$from_name_safe  = safe_header_value(MAIL_FROM_NAME);
$from_email_safe = safe_header_value(MAIL_FROM_EMAIL);

// Build headers
$headers  = "MIME-Version: 1.0" . PHP_EOL;
$headers .= "Content-Type: text/html; charset=UTF-8" . PHP_EOL;
$headers .= "From: {$from_name_safe} <{$from_email_safe}>" . PHP_EOL;

// Reply-To: if we have a valid sender email, set a Reply-To (safe)
if ($sender_email !== '' && is_valid_email($sender_email)) {
    $headers .= "Reply-To: " . safe_header_value($sender_email) . PHP_EOL;
}

// Send
$subject_safe = '=?UTF-8?B?'.base64_encode($form_subject).'?=';
$sent = mail(ADMIN_RECIPIENT, $subject_safe, $message_html, $headers);

if ($sent) {
    echo json_encode(['status' => 'ok', 'message' => 'Message sent.']);
} else {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Failed to send message.']);
}
