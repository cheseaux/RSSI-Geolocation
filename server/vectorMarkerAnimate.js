// Animated Vector Marker. Alessio Cimarelli 2013 https://github.com/jenkin/vector-marker-animate
// MIT license
//
// params:
// map                - the google map where place the marker (not for fadeOut)
// options            - optional options object (optional)
// options.duration   - animation duration in ms (default 1000)
// options.easing     - easing function from jQuery and/or the jQuery easing plugin (default 'linear')
// options.complete   - callback function. Gets called, after the animation has finished
google.maps.Marker.prototype.bindCircle = function(options) {
    var options = options || {};
    this.setVisible(false);
    this.circle = new google.maps.Circle(options);
    this.circle.bindTo('map',this);
    this.circle.bindTo('center',this,'position');
}


/***************** GROW UP ********************/
google.maps.Marker.prototype.growUp = function(map, options) {
  defaultOptions = {
    duration: 1000,
    easing: 'linear',
    complete: null
  }
  options = options || {};

  // complete missing options
  for (key in defaultOptions) {
    options[key] = options[key] || defaultOptions[key];
  }

  // throw exception if easing function doesn't exist
  if (options.easing != 'linear') {            
    if (typeof jQuery == 'undefined' || !jQuery.easing[options.easing]) {
      throw '"' + options.easing + '" easing function doesn\'t exist. Include jQuery and/or the jQuery easing plugin and use the right function name.';
      return;
    }
  }
  
  // Throw exception if marker.circle is not defined
  if (!this.hasOwnProperty("circle")) {
    throw 'There is no circle binded to marker to animate! Before growUp() you have to call marker.bindCircle({options}).';
    return;
  }

  window.requestAnimationFrame = window.requestAnimationFrame || window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.msRequestAnimationFrame;
  window.cancelAnimationFrame = window.cancelAnimationFrame || window.mozCancelAnimationFrame;

  // save finale circle radius. prefixed to avoid name collisions.
  this.circle.jnkEndRadius = this.circle.getRadius();
  this.circle.jnkStartRadius = 0;
  
  this.circle.setRadius(this.jnkStartRadius);
  this.setMap(map);

  var animateStep = function(marker, startTime) {            
    var ellapsedTime = (new Date()).getTime() - startTime;
    var durationRatio = ellapsedTime / options.duration; // 0 - 1
    var easingDurationRatio = durationRatio;

    // use jQuery easing if it's not linear
    if (options.easing !== 'linear') {
      easingDurationRatio = jQuery.easing[options.easing](durationRatio, ellapsedTime, 0, 1, options.duration);
    }
    
    if (durationRatio < 1) {
      var deltaRadius = marker.circle.jnkStartRadius + (marker.circle.jnkEndRadius - marker.circle.jnkStartRadius)*easingDurationRatio;
      
      marker.circle.setRadius(deltaRadius);

      // use requestAnimationFrame if it exists on this browser. If not, use setTimeout with ~60 fps
      if (window.requestAnimationFrame) {
        marker.jnkAnimationHandler = window.requestAnimationFrame(function() {animateStep(marker, startTime)});                
      } else {
        marker.jnkAnimationHandler = setTimeout(function() {animateStep(marker, startTime)}, 17); 
      }

    } else {
      
      marker.circle.setRadius(marker.circle.jnkEndRadius);

      if (typeof options.complete === 'function') {
        options.complete();
      }

    }            
  }

  // stop possibly running animation
  if (window.cancelAnimationFrame) {
    window.cancelAnimationFrame(this.jnkAnimationHandler);
  } else {
    clearTimeout(this.jnkAnimationHandler); 
  }
  
  animateStep(this, (new Date()).getTime());
}


/***************** FADE IN (defunct) ********************/
google.maps.Marker.prototype.fadeIn = function(map, options) {
  defaultOptions = {
    duration: 1000,
    easing: 'linear',
    complete: null
  }
  options = options || {};

  // complete missing options
  for (key in defaultOptions) {
    options[key] = options[key] || defaultOptions[key];
  }

  // throw exception if easing function doesn't exist
  if (options.easing != 'linear') {            
    if (typeof jQuery == 'undefined' || !jQuery.easing[options.easing]) {
      throw '"' + options.easing + '" easing function doesn\'t exist. Include jQuery and/or the jQuery easing plugin and use the right function name.';
      return;
    }
  }
  
  // Throw exception if marker.circle is not defined
  if (!this.hasOwnProperty("circle")) {
    throw 'There is no circle binded to marker to animate! Before fadeIn() you have to call marker.bindCircle({options}).';
    return;
  }

  window.requestAnimationFrame = window.requestAnimationFrame || window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.msRequestAnimationFrame;
  window.cancelAnimationFrame = window.cancelAnimationFrame || window.mozCancelAnimationFrame;

  // save finale circle radius. prefixed to avoid name collisions.
  this.circle.jnkEndFillOpacity = this.circle.fillOpacity || 1;
  this.circle.jnkEndStrokeOpacity = this.circle.strokeOpacity || 1;
  this.circle.jnkStartFillOpacity = 0;
  this.circle.jnkStartStrokeOpacity = 0;
  
  this.circle.setOptions({fillOpacity: 0, strokeOpacity: 0});
  this.setMap(map);

  var animateStep = function(marker, startTime) {            
    var ellapsedTime = (new Date()).getTime() - startTime;
    var durationRatio = ellapsedTime / options.duration; // 0 - 1
    var easingDurationRatio = durationRatio;

    // use jQuery easing if it's not linear
    if (options.easing !== 'linear') {
      easingDurationRatio = jQuery.easing[options.easing](durationRatio, ellapsedTime, 0, 1, options.duration);
    }
    
    if (durationRatio < 1) {
      var deltaFillOpacity = marker.circle.jnkStartFillOpacity + (marker.circle.jnkEndFillOpacity - marker.circle.jnkStartFillOpacity)*easingDurationRatio;
      var deltaStrokeOpacity = marker.circle.jnkStartStrokeOpacity + (marker.circle.jnkEndStrokeOpacity - marker.circle.jnkStartStrokeOpacity)*easingDurationRatio;
      
      marker.circle.setOptions({fillOpacity: deltaFillOpacity, strokeOpacity: deltaStrokeOpacity});

      // use requestAnimationFrame if it exists on this browser. If not, use setTimeout with ~60 fps
      if (window.requestAnimationFrame) {
        marker.jnkAnimationHandler = window.requestAnimationFrame(function() {animateStep(marker, startTime)});                
      } else {
        marker.jnkAnimationHandler = setTimeout(function() {animateStep(marker, startTime)}, 17); 
      }

    } else {
      
      marker.circle.setOptions({fillOpacity: marker.circle.jnkEndFillOpacity, strokeOpacity: marker.circle.jnkEndStrokeOpacity});

      if (typeof options.complete === 'function') {
        options.complete();
      }

    }            
  }

  // stop possibly running animation
  if (window.cancelAnimationFrame) {
    window.cancelAnimationFrame(this.jnkAnimationHandler);
  } else {
    clearTimeout(this.jnkAnimationHandler); 
  }
  
  animateStep(this, (new Date()).getTime());
}


/***************** FADE OUT ********************/
google.maps.Marker.prototype.fadeOut = function(options) {
  defaultOptions = {
    duration: 1000,
    easing: 'linear',
    complete: null
  }
  options = options || {};

  // complete missing options
  for (key in defaultOptions) {
    options[key] = options[key] || defaultOptions[key];
  }

  // throw exception if easing function doesn't exist
  if (options.easing != 'linear') {            
    if (typeof jQuery == 'undefined' || !jQuery.easing[options.easing]) {
      throw '"' + options.easing + '" easing function doesn\'t exist. Include jQuery and/or the jQuery easing plugin and use the right function name.';
      return;
    }
  }
  
  // Throw exception if marker.circle is not defined
  if (!this.hasOwnProperty("circle")) {
    throw 'There is no circle binded to marker to animate! Before fadeOut() you have to call marker.bindCircle({options}).';
    return;
  }

  window.requestAnimationFrame = window.requestAnimationFrame || window.mozRequestAnimationFrame || window.webkitRequestAnimationFrame || window.msRequestAnimationFrame;
  window.cancelAnimationFrame = window.cancelAnimationFrame || window.mozCancelAnimationFrame;

  // save finale circle radius. prefixed to avoid name collisions.
  this.circle.jnkStartFillOpacity = this.circle.fillOpacity || 1.0;
  this.circle.jnkStartStrokeOpacity = this.circle.strokeOpacity || 1.0;
  this.circle.jnkEndFillOpacity = 0;
  this.circle.jnkEndStrokeOpacity = 0;

  var animateStep = function(marker, startTime) {            
    var ellapsedTime = (new Date()).getTime() - startTime;
    var durationRatio = ellapsedTime / options.duration; // 0 - 1
    var easingDurationRatio = durationRatio;

    // use jQuery easing if it's not linear
    if (options.easing !== 'linear') {
      easingDurationRatio = jQuery.easing[options.easing](durationRatio, ellapsedTime, 0, 1, options.duration);
    }
    
    if (durationRatio < 1) {
      var deltaFillOpacity = marker.circle.jnkStartFillOpacity + (marker.circle.jnkEndFillOpacity - marker.circle.jnkStartFillOpacity)*easingDurationRatio;
      var deltaStrokeOpacity = marker.circle.jnkStartStrokeOpacity + (marker.circle.jnkEndStrokeOpacity - marker.circle.jnkStartStrokeOpacity)*easingDurationRatio;
      
      marker.circle.setOptions({fillOpacity: deltaFillOpacity, strokeOpacity: deltaStrokeOpacity});

      // use requestAnimationFrame if it exists on this browser. If not, use setTimeout with ~60 fps
      if (window.requestAnimationFrame) {
        marker.jnkAnimationHandler = window.requestAnimationFrame(function() {animateStep(marker, startTime)});                
      } else {
        marker.jnkAnimationHandler = setTimeout(function() {animateStep(marker, startTime)}, 17); 
      }

    } else {
      
      marker.circle.setOptions({fillOpacity: marker.circle.jnkEndFillOpacity, strokeOpacity: marker.circle.jnkEndStrokeOpacity});
      marker.setMap(null);
      marker.circle.setOptions({fillOpacity: marker.circle.jnkStartFillOpacity, strokeOpacity: marker.circle.jnkStartStrokeOpacity});

      if (typeof options.complete === 'function') {
        options.complete();
      }

    }            
  }

  // stop possibly running animation
  if (window.cancelAnimationFrame) {
    window.cancelAnimationFrame(this.jnkAnimationHandler);
  } else {
    clearTimeout(this.jnkAnimationHandler); 
  }
  
  animateStep(this, (new Date()).getTime());
}
