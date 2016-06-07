<?xml version="1.0" encoding="ISO-8859-1"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output
        method="html"
        indent="yes"
        encoding="ISO-8859-1"
/>

<xsl:variable name="date1" select="string(/logs/req_date)" />
<xsl:variable name="machine1" select="string(/logs/req_machine)" />

<xsl:template match="/">
<html>
        <head>
                <title>Samhain Log</title>
        </head>
        <body bgcolor="black" text="white" link="0077CC" vlink="0077CC" alink="FFFFFF">
        <center>
        <table bgcolor="777777" border="0" cellpadding="0" cellspacing="0">
                <tr><td><img src="samhain.png"/></td></tr>
                <tr><td><center><h1>Logs Samhain</h1></center></td></tr>
        </table><br/>
        <hr/>
        <table bgcolor="black" border="0" cellpadding="0" cellspacing="0">
                <form action="samhain.cgi" method="post">
                <tr>
                        <td>Date: <input type="text" name="date">
				<xsl:attribute name="value">
					<xsl:value-of select="$date1" />
				</xsl:attribute>
				</input>
			</td>
                        <td>Machine: <input type="text" name="machine">
				<xsl:attribute name="value">
					<xsl:value-of select="$machine1" />
				</xsl:attribute>
				</input>
			</td>
                        <td><input type="submit" value="afficher"/></td>
                </tr>
                </form>
        </table><br/>
        <hr/>
                <table bgcolor="222222" border="1" cellpadding="1" cellspacing="5">
                        <tr bgcolor="777777">
                                <td>TYPE D'ALERTE</td>
                                <td>CHEMIN</td>
                                <td>MESSAGE</td>
                                <td>DATE</td>
                                <td>MACHINE</td>
                        </tr>
                        <xsl:apply-templates />
                </table>
        <hr/>
        </center>
        </body>
</html>
</xsl:template>

<xsl:template match="sig">
</xsl:template>

<xsl:template match="req_date">
</xsl:template>

<xsl:template match="req_machine">
</xsl:template>

<xsl:template match="log">
        <tr>
                <xsl:variable name="sev1" select="@sev"/>
                <xsl:if test='$sev1="ALRT"'>
                        <td bgcolor="orange"><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="MARK"'>
                        <td bgcolor="blue"><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="CRIT"'>
                        <td bgcolor="red"><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="WARN"'>
                        <td><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="INFO"'>
                        <td><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="NOTE"'>
                        <td><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="DEBG"'>
                        <td><xsl:value-of select="@sev"/></td>
                </xsl:if>
		<xsl:choose>
                <xsl:when test='$sev1="RCVT"'>
                        <td bgcolor="green"><xsl:value-of select="@sev"/></td>
			<td><xsl:value-of select="log@path"/></td>
                	<td><xsl:value-of select="log@msg"/></td>
                	<td><xsl:value-of select="log@tstamp"/></td>
                	<td><xsl:value-of select="@remote_host"/></td>
		</xsl:when>
		<xsl:otherwise>
                <td><xsl:value-of select="@path"/></td>
                <td><xsl:value-of select="@msg"/></td>
                <td><xsl:value-of select="@tstamp"/></td>
                <td><xsl:value-of select="@host"/></td>
		</xsl:otherwise>
		</xsl:choose>
        </tr>
</xsl:template>

<xsl:template match="trail/log">
        <xsl:if test='starts-with(@remote_host,$machine1)'>
	<xsl:if test='starts-with(@tstamp,$date1)'>
        <tr>
                <xsl:variable name="sev1" select="@sev"/>
                <xsl:if test='$sev1="ALRT"'>
                        <td bgcolor="orange"><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="MARK"'>
                        <td bgcolor="blue"><xsl:value-of select="@sev"/></td>
                </xsl:if>
                <xsl:if test='$sev1="CRIT"'>
                        <td bgcolor="red"><xsl:value-of select="@sev"/></td>
                </xsl:if>
		<xsl:choose>
                <xsl:when test='$sev1="RCVT"'>
                        <td bgcolor="green"><xsl:value-of select="@sev"/></td>
			<td><xsl:value-of select="log@path"/></td>
                	<td><xsl:value-of select="log@msg"/></td>
                	<td><xsl:value-of select="log@tstamp"/></td>
                	<td><xsl:value-of select="@remote_host"/></td>
		</xsl:when>
		<xsl:otherwise>
                <td><xsl:value-of select="@path"/></td>
                <td><xsl:value-of select="@msg"/></td>
                <td><xsl:value-of select="@tstamp"/></td>
                <td><xsl:value-of select="@remote_host"/></td>
		</xsl:otherwise>
		</xsl:choose>
        </tr>
        <xsl:apply-templates/>
        </xsl:if>
        </xsl:if>
</xsl:template>


</xsl:stylesheet>
