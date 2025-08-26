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
    <xsl:variable name="clean" select="translate($lower, ' /&quot;-()', '____')" />
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

  <xsl:template name="append-network">
    <xsl:param name="alias" />
    <xsl:param name="set"/>
    <xsl:text>    define </xsl:text>
    <xsl:value-of select="concat($prefix, '_', $set)"/>
    <xsl:text> += </xsl:text>
    <xsl:value-of select="$alias"/>
    <xsl:text>&#10;</xsl:text>
  </xsl:template>


  <xsl:template match="/">
    <xsl:for-each select="//iana:record">
      <xsl:variable name="pos" select="position()" />
      <xsl:variable name="name_raw" select="normalize-space(translate(iana:name, '&quot;', ''))" />
      <xsl:variable name="snake_case_name">
        <xsl:call-template name="snake-case">
          <xsl:with-param name="text" select="$name_raw"/>
        </xsl:call-template>
      </xsl:variable>

      <xsl:variable name="base_name">
        <xsl:value-of select="concat($prefix, '_', $snake_case_name)" />
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
            <xsl:value-of select="concat($base_name, '_', $suffix)" />
          </xsl:when>
          <xsl:otherwise>
            <xsl:value-of select="$base_name" />
          </xsl:otherwise>
        </xsl:choose>
      </xsl:variable>

      <!-- Main define line -->
      <xsl:choose>
        <!-- Cannot filter on source in this case, as SNAT may be applied to the source address -->
        <xsl:when test="$name_raw = 'Private-Use'">
          <xsl:value-of select="concat('define ', $prefix, '_', $snake_case_name, ' += [',
                                iana:address, '] # ', $name_raw, '&#10;')" />
        </xsl:when>
        <xsl:otherwise>
          <xsl:value-of select="concat('define ', $alias, ' = [',
                                iana:address, '] # ', $name_raw, '&#10;')" />

          <!-- Always add to all -->
          <xsl:call-template name="append-network">
            <xsl:with-param name="alias" select="$alias" />
            <xsl:with-param name="set" select="'all'" />
          </xsl:call-template>

          <!-- Conditional groupings -->
          <xsl:if test="iana:source = 'True'">
            <xsl:call-template name="append-network">
              <xsl:with-param name="alias" select="$alias" />
              <xsl:with-param name="set" select="'source'" />
            </xsl:call-template>
          </xsl:if>

          <xsl:if test="iana:destination = 'True'">
            <xsl:call-template name="append-network">
              <xsl:with-param name="alias" select="$alias" />
              <xsl:with-param name="set" select="'destination'" />
            </xsl:call-template>
          </xsl:if>

          <xsl:if test="iana:forwardable = 'True'">
            <xsl:call-template name="append-network">
              <xsl:with-param name="alias" select="$alias" />
              <xsl:with-param name="set" select="'forwardable'" />
            </xsl:call-template>
          </xsl:if>

          <xsl:if test="iana:global = 'True'">
            <xsl:call-template name="append-network">
              <xsl:with-param name="alias" select="$alias" />
              <xsl:with-param name="set" select="'global'" />
            </xsl:call-template>
          </xsl:if>

          <xsl:if test="iana:termination">
            <xsl:call-template name="append-network">
              <xsl:with-param name="alias" select="$alias" />
              <xsl:with-param name="set" select="'terminated'" />
            </xsl:call-template>
          </xsl:if>

        </xsl:otherwise>
      </xsl:choose>
      <xsl:text>&#10;</xsl:text>
    </xsl:for-each>
  </xsl:template>
</xsl:stylesheet>
