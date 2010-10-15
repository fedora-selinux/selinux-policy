<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform">

  <xsl:template match="/sigs">
    <h1>SELinux Policy Faults</h1>
    <table border="1" cellpadding="5">
      <tr>
	<td><b>Plugin</b></td>
	<td><b>Filter</b></td>
	<td><b>Summary</b></td>
      </tr>
    <xsl:for-each select="SignatureList/sigInfo">
      <tr>
	<td><xsl:value-of select="substring-after(sig/analysisID,'plugins.')"/></td>
	<!--<xsl:value-of select="filterList/filter/filter_type"/-->
	<td>
	  <form action="submit" method="post">
	    <SELECT name="filter_select_1">
	      <OPTION value='FILTER_NEVER'>Never Ignore</OPTION>
	      <OPTION value='FILTER_TILL_FIX'>Ignore Until Fix Released</OPTION>
	      <OPTION value='FILTER_TILL_RPM_CHANGE'>Ignore Until RPM Updated</OPTION>
	      <OPTION value='FILTER_TILL_POLICY_CHANGE'>Ignore Until Policy Updated</OPTION>
	    </SELECT>
	    <input type="submit" value="Submit"/>
	  </form>
	</td>
	<td><xsl:value-of select="solution/summary"/></td>
      </tr>
    </xsl:for-each>
    </table>
  </xsl:template>
  
</xsl:stylesheet>
