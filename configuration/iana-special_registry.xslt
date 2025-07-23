
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:iana="http://www.iana.org/assignments"
  exclude-result-prefixes="iana">

  <!-- xsltproc \-\-stringparam prefix ip6 your_stylesheet.xsl
       your_data.xml -->
  <xsl:output method="text" encoding="UTF-8" />

  <!-- Prefix parameter: ip4 (default) or ip6 -->
  <xsl:param name="prefix" select="'ip4'" />

  <!-- snake_case conversion -->
  <xsl:template name="snake-case">
    <xsl:param name="text" />
    <xsl:variable name="lower" select="translate($text, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')" />
    <xsl:variable name="clean" select="translate($lower, ' &quot;-()', '__')" />
    <xsl:value-of select="normalize-space($clean)" />
  </xsl:template>

  <!-- Count duplicates -->
  <xsl:template name="count-duplicates">
    <xsl:param name="current-pos" />
    <xsl:param name="target" />
    <xsl:variable name="count"
      select="count(//iana:record[position() &lt; $current-pos][normalize-space(translate(iana:name, '&quot;', '')) = $target]) + 1" />
    <xsl:value-of select="$count" />
  </xsl:template>

  <xsl:template match="/">
    <xsl:for-each select="//iana:record">
      <xsl:variable name="pos" select="position()" />
      <xsl:variable name="name_raw" select="normalize-space(translate(iana:name, '&quot;', ''))" />
      <xsl:variable name="snake_base">
        <xsl:call-template name="snake-case">
          <xsl:with-param name="text" select="$name_raw"/>
        </xsl:call-template>
      </xsl:variable>
      <xsl:variable name="suffix">
        <xsl:call-template name="count-duplicates">
          <xsl:with-param name="current-pos" select="$pos" />
          <xsl:with-param name="target" select="$name_raw" />
        </xsl:call-template>
      </xsl:variable>
      <xsl:variable name="alias">
        <xsl:choose>
          <xsl:when test="$suffix &gt; 1">
            <xsl:value-of select="concat($snake_base, '_', $suffix)" />
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="$snake_base" />
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>

      <!-- Main define line -->
      <xsl:text>define </xsl:text>
      <xsl:value-of select="$prefix" />
      <xsl:text>_</xsl:text>
      <xsl:value-of select="$alias" />
      <xsl:text> = </xsl:text>
      <xsl:value-of select="iana:address" />
      <xsl:text> # </xsl:text>
      <xsl:value-of select="$name_raw" />
      <xsl:text>
</xsl:text>

      <!-- Always add to all -->
      <xsl:text>define </xsl:text>
      <xsl:value-of select="$prefix" />
      <xsl:text>_all += </xsl:text>
      <xsl:value-of select="$prefix" />
      <xsl:text>_</xsl:text>
      <xsl:value-of select="$alias" />
      <xsl:text>
</xsl:text>

      <!-- Conditional groupings -->
      <xsl:if test="iana:source = 'True'">
        <xsl:text>    define </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_source += </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_</xsl:text>
        <xsl:value-of select="$alias" />
        <xsl:text>
</xsl:text>
      </xsl:if>

      <xsl:if test="iana:destination = 'True'">
        <xsl:text>    define </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_destination += </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_</xsl:text>
        <xsl:value-of select="$alias" />
        <xsl:text>
</xsl:text>
      </xsl:if>

      <xsl:if test="iana:forwardable = 'True'">
        <xsl:text>    define </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_forwardable += </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_</xsl:text>
        <xsl:value-of select="$alias" />
        <xsl:text>
</xsl:text>
      </xsl:if>

      <xsl:if test="iana:global = 'True'">
        <xsl:text>    define </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_global += </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_</xsl:text>
        <xsl:value-of select="$alias" />
        <xsl:text>
</xsl:text>
      </xsl:if>

      <!-- Termination check → reserved -->
      <xsl:if test="iana:termination">
        <xsl:text>    define </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_reserved += </xsl:text>
        <xsl:value-of select="$prefix" />
        <xsl:text>_</xsl:text>
        <xsl:value-of select="$alias" />
        <xsl:text>
</xsl:text>
      </xsl:if>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
