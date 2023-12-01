echo "========================================================================"
echo "verify: elna-leaf -> elna-intermediate -> elna-root"
openssl verify -CAfile elna-root.pem -untrusted elna-intermediate.pem elna-leaf.pem

echo "========================================================================"
echo "verify: elna-leaf -> elna-intermediate-cross-signed-by-diya -> diya-root"
openssl verify -CAfile diya-root.pem -untrusted elna-intermediate-cs-diya.pem elna-leaf.pem