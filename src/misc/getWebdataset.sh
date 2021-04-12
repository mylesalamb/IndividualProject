# curl -H "Accept: application/json" -H "x-api-key: VBZRJ6Gr704MpWV3NLGUIadxtP5laM4H41CQyK7V" "https://ats.api.alexa.com/api?Action=Topsites&Count=100&CountryCode=BR&ResponseGroup=Country&Start=301&Output=json"


# Script for getting websites from the alexa top sites list
OUTFILE=web.alexa.raw

echo "[" > $OUTFILE
for i in {1..1500}; do
curl -H "Accept: application/json" -H "x-api-key: VBZRJ6Gr704MpWV3NLGUIadxtP5laM4H41CQyK7V" "https://ats.api.alexa.com/api?Action=Topsites&Count=1&CountryCode=US&ResponseGroup=Country&Start=${i}&Output=json" >> $OUTFILE
echo "," >> $OUTFILE
done

echo "]" >> $OUTFILE

exit 0 
