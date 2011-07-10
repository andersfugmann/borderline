<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" 
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:iana="http://www.iana.org/assignments">
<xsl:output method="text"/>

<xsl:template match="iana:registry">
<xsl:for-each select="iana:record[iana:status='ALLOCATED']">
<xsl:value-of select="iana:prefix"/>,
</xsl:for-each>
</xsl:template>

</xsl:stylesheet>

              
