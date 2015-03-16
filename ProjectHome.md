<b>What is this TIP stuff all about?</b><br>
The <a href='http://rootedyour.com/tip'>Threat Intelligence Project (TIP)</a> was created to collect information from snort sensors around the globe.<br>
<br>
<b>Goals</b><br>
The goal is to provide useful threat metrics from this data, that include some subjective input (False Positives as submitted by sensor operators).<br>
<br>
<b>Example Metrics:</b>
<ul><li>IP reputation<br>
</li><li>Global Rule hit-count<br>
</li><li>Rule accuracy<br>
</li><li>Packet data (payload)<br>
</li><li>Many more to come, please feel free to make suggestion/requests!</li></ul>

Currently we are developing the client / server components that will collect the data and submit it in a secure fashion.  The initial release will have allow the participant to obfuscate ip information (source or dest), payload information (your pakets), none, or both!