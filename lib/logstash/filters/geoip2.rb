# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "tempfile"

# The GeoIP filter adds information about the geographical location of IP addresses,
# based on data from the Maxmind database.
#
# Starting with version 1.3.0 of Logstash, a `[geoip][location]` field is created if
# the GeoIP lookup returns a latitude and longitude. The field is stored in
# http://geojson.org/geojson-spec.html[GeoJSON] format. Additionally,
# the default Elasticsearch template provided with the
# <<plugins-outputs-elasticsearch,`elasticsearch` output>> maps
# the `[geoip][location]` field to an http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/mapping-geo-point-type.html#_mapping_options[Elasticsearch geo_point].
#
# As this field is a `geo_point` _and_ it is still valid GeoJSON, you get
# the awesomeness of Elasticsearch's geospatial query, facet and filter functions
# and the flexibility of having GeoJSON for all other applications (like Kibana's
# map visualization).
#
# Logstash releases ship with the GeoLiteCity database made available from
# Maxmind with a CCA-ShareAlike 3.0 license. For more details on GeoLite, see
# <http://www.maxmind.com/en/geolite>.
class LogStash::Filters::GeoIP2 < LogStash::Filters::Base
  config_name "geoip2"

  # The path to the GeoIP database file which Logstash should use. Country, City, ASN, ISP
  # and organization databases are supported.
  #
  # If not specified, this will default to the GeoLiteCity database that ships
  # with Logstash.
  config :databases, :validate => :array


  # The field containing the IP address or hostname to map via geoip. If
  # this field is an array, only the first value will be used.
  config :source, :validate => :string, :required => true

  # An array of geoip fields to be included in the event.
  #
  # Possible fields depend on the database type. By default, all geoip fields
  # are included in the event.
  #
  # For the built-in GeoLiteCity database, the following are available:
  # `city_name`, `continent_code`, `country_code2`, `country_code3`, `country_name`,
  # `dma_code`, `ip`, `latitude`, `longitude`, `postal_code`, `region_name` and `timezone`.
  config :fields, :validate => :array

  # Specify the field into which Logstash should store the geoip data.
  # This can be useful, for example, if you have `src\_ip` and `dst\_ip` fields and
  # would like the GeoIP information of both IPs.
  #
  # If you save the data to a target field other than `geoip` and want to use the
  # `geo\_point` related functions in Elasticsearch, you need to alter the template
  # provided with the Elasticsearch output and configure the output to use the
  # new template.
  #
  # Even if you don't use the `geo\_point` mapping, the `[target][location]` field
  # is still valid GeoJSON.
  config :target, :validate => :string, :default => 'geoip'

  public
  def register
    require "geoip"
    @geotypes = Hash.new
    if @databases.nil? || @databases.empty?
      @databases = Array.new if @databases.nil?
      geodefault = ::Dir.glob(::File.join(::File.expand_path("../../../vendor/", ::File.dirname(__FILE__)),"GeoLiteCity*.dat")).first
      @databases << geodefault
    end
    @databases.each do |database|
      if !File.exists?(database)
         raise "invalid path '#{database}',file no found"
      end
      geoip_initialize = ::GeoIP.new(database)
      geoip_type = case geoip_initialize.database_type
        when GeoIP::GEOIP_CITY_EDITION_REV0, GeoIP::GEOIP_CITY_EDITION_REV1
          :city
        when GeoIP::GEOIP_COUNTRY_EDITION
          :country
        when GeoIP::GEOIP_ASNUM_EDITION
          :asn
        when GeoIP::GEOIP_ISP_EDITION, GeoIP::GEOIP_ORG_EDITION
          :isp
        else
          raise RuntimeException.new "This GeoIP database is not currently supported"
      end
      if @geotypes.has_value?(geoip_type)
        raise RuntimeException.new "This GeoIP database '#{database}' conflict whith other database"
      end
      @geotypes[database] = geoip_type
    end
    # For the purpose of initializing this filter, geoip is initialized here but
    # not set as a global. The geoip module imposes a mutex, so the filter needs
    # to re-initialize this later in the filter() thread, and save that access
    # as a thread-local variable.


    
  end # def register

  public
  def filter(event)
    return unless filter?(event)
    geo_data_hash = Hash.new

    # Use thread-local access to GeoIP. The Ruby GeoIP module forces a mutex
    # around access to the database, which can be overcome with :pread.
    # Unfortunately, :pread requires the io-extra gem, with C extensions that
    # aren't supported on JRuby. If / when :pread becomes available, we can stop
    # needing thread-local access.


    
    ip = event[@source]
    ip = ip.first if ip.is_a? Array
    @databases.each do |database|
      if !Thread.current.key?("geoip-#{database}")
        Thread.current["geoip-#{database}"] = ::GeoIP.new(database)
      end
      begin
        geo_data_tmp = Thread.current["geoip-#{database}"].send(@geotypes[database], ip)
        geo_data_hash = geo_data_hash.merge(geo_data_tmp.to_hash) if geo_data_tmp.respond_to?(:to_hash)
        rescue SocketError => e
          @logger.error("IP Field contained invalid IP address or hostname",  :event => event)
        rescue Exception => e
          @logger.error("Unknown error while looking up GeoIP data", :exception => e, :event => event)
      end
    end


    geo_data_hash.delete(:request)
    event[@target] = {} if event[@target].nil?
    if geo_data_hash.key?(:latitude) && geo_data_hash.key?(:longitude)
      # If we have latitude and longitude values, add the location field as GeoJSON array
      geo_data_hash[:location] = [ geo_data_hash[:longitude].to_f, geo_data_hash[:latitude].to_f ]
    end
    geo_data_hash.each do |key, value|
      next if value.nil? || (value.is_a?(String) && value.empty?)
      if @fields.nil? || @fields.empty? || @fields.include?(key.to_s)
        # convert key to string (normally a Symbol)
        if value.is_a?(String)
          # Some strings from GeoIP don't have the correct encoding...
          value = case value.encoding
            # I have found strings coming from GeoIP that are ASCII-8BIT are actually
            # ISO-8859-1...
            when Encoding::ASCII_8BIT; value.force_encoding(Encoding::ISO_8859_1).encode(Encoding::UTF_8)
            when Encoding::ISO_8859_1, Encoding::US_ASCII;  value.encode(Encoding::UTF_8)
            else; value
          end
        end
        event[@target][key.to_s] = value
      end
    end # geo_data_hash.each
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::GeoIP
