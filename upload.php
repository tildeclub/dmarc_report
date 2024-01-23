<?php
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES["dmarcReport"])) {
    $file = $_FILES["dmarcReport"]["tmp_name"];
    $fileType = strtolower(pathinfo($_FILES["dmarcReport"]["name"], PATHINFO_EXTENSION));
    $fileError = $_FILES["dmarcReport"]["error"];

    // Start of HTML output
    echo '<!DOCTYPE html><html><head><title>DMARC Report Output</title>';
    echo '<link rel="stylesheet" href="css/style.css"></head><body>';

    // Check for file upload errors
    if ($fileError !== UPLOAD_ERR_OK) {
        echo "<p class='error'>Error in file upload: " . $fileError . "</p>";
        exit;
    }

    // Validate file type (XML)
    if ($fileType != "xml") {
        echo "<p class='error'>Only XML files are allowed.</p>";
        exit;
    }

    // Load XML file
    libxml_use_internal_errors(true);
    $xml = simplexml_load_file($file);
    $errors = libxml_get_errors();
    libxml_clear_errors();

    // Check if it's a valid DMARC XML
    if ($xml === false || !empty($errors)) {
        echo "<p class='error'>Failed to parse the XML file. Ensure it's a valid DMARC report.</p>";
        foreach ($errors as $error) {
            echo "<p class='error-detail'>Error: " . htmlspecialchars($error->message) . "</p>";
        }
        exit;
    }

    // Verify XML structure
    if (!isset($xml->report_metadata, $xml->policy_published, $xml->record)) {
        echo "<p class='error'>Invalid DMARC report structure.</p>";
        exit;
    }

    // Extract and display data
    echo "<h2>DMARC Report Summary</h2>";
    $orgName = $xml->report_metadata->org_name;
    echo "<p>Organization: $orgName</p>";

    $domain = $xml->policy_published->domain;
    $policy = $xml->policy_published->p;
    echo "<p>Domain: $domain</p>";
    echo "<p>Policy: $policy</p>";

    // Process record data
    echo "<h3>Details of Email Activity</h3>";
    echo "<table><thead><tr><th>Source IP</th><th>Email Count</th><th>SPF Result</th><th>DKIM Result</th><th>Explanation</th></tr></thead><tbody>";
    foreach ($xml->record as $record) {
        $sourceIp = $record->row->source_ip;
        $count = $record->row->count;
        $evaluatedPolicy = $record->row->policy_evaluated;
        $spfResult = $evaluatedPolicy->spf;
        $dkimResult = $evaluatedPolicy->dkim;

        echo "<tr>";
        echo "<td>$sourceIp</td>";
        echo "<td>$count</td>";
        echo "<td>$spfResult</td>";
        echo "<td>$dkimResult</td>";

        // Plain English Explanation
        $explanation = getExplanation($spfResult, $dkimResult);
        echo "<td>$explanation</td>";
        echo "</tr>";
    }
    echo "</tbody></table>";

    echo '</body></html>';
}

function getExplanation($spfResult, $dkimResult) {
    if ($spfResult == "pass" && $dkimResult == "pass") {
        return "Both SPF and DKIM checks passed. Emails are likely legitimate.";
    } elseif ($spfResult == "fail" && $dkimResult == "fail") {
        return "Both SPF and DKIM checks failed. Emails could be fraudulent.";
    } else {
        return "Mixed results. Further investigation needed.";
    }
}
?>
