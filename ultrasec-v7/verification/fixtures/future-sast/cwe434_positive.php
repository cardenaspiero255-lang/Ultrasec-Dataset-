<?php
function upload_file($tmp, $destination) {
    move_uploaded_file($tmp, $destination);
}
