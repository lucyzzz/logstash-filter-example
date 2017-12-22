# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require 'rubygems'
require 'json'
require 'pp'
require 'yaml'

# This  filter will replace the contents of the default 
# message field with whatever you specify in the configuration.
#
# It is only intended to be used as an .
class LogStash::Filters::attackfilter < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your Logstash config.
  #
  # filter {
  #    {
  #     message => "My message..."
  #   }
  # }
  #
  config_name "attackfilter"
  
  # Replace the message with this value.
  config :message, :validate => :string, :default => "Hello World!"
  

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)
    if @message
      # Replace the event message with our message as configured in the
      # config file.
      attack_filter(@message)
      #event.set("message", @message)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::attackfilter


def attack_filter(messages)
  problem = YAML.load(File.open('/opt/rule.yaml'))
  problem["data"]["sql"].each_with_index do |sql,i|
      #  puts "id: #{sql['id']}"
      #  puts "regex: #{sql['regex']}"
      #  puts "place: #{sql['place']}"
      #  puts "typename: #{sql['typename']}"
       reg3 = Regexp.new "#{sql['regex']}"[0..-1] 
       if reg3 =~ messages
          ccc = "检测出存在 #{sql['typename']}  #{messages}" 
          event.set("message", ccc)
          break
       end
  end
end
